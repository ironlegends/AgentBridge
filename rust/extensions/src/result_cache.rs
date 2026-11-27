//! Bounded per-live-registry cache. No token, caller-supplied identity,
//! upstream raw payload, or cache key is ever logged or serialized.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest,Sha256};
use std::{collections::HashMap,sync::{Arc,Mutex},time::{Duration,Instant}};
use crate::CancellationToken;

const MAX_ENTRIES:usize=256;
const MAX_BYTES:usize=64*1024;
const MAX_TTL:u64=300;

/// Explicit local per-tool permission. Absence keeps old behavior and
/// fingerprints. An upstream annotation alone grants nothing.
#[derive(Clone,Copy,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub read_only:bool,
    pub ttl_seconds:u64,
}
impl Policy {
    pub(crate) fn valid(self,descriptor:&Value)->bool {
        self.read_only && (1..=MAX_TTL).contains(&self.ttl_seconds)
            && descriptor["annotations"]["readOnlyHint"]==true
            && matches!(descriptor["annotations"].get("destructiveHint"),None|Some(Value::Bool(false)))
    }
}

// This is trusted host input only, supplied by the authenticated transport;
// no Deserialize, Debug or Display implementation and no raw token.
#[derive(Clone,Copy)]
pub(crate) struct CacheCaller {
    token_hash:[u8;32],
    profile:u8,
}
impl CacheCaller {
    pub(crate) fn authenticated(token_hash:[u8;32],profile:u8)->Option<Self>{
        (profile<=3).then_some(Self{token_hash,profile})
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Hash)]
struct Key([u8;32]);
impl Key {
    fn new(server:&str,tool:&str,descriptor:&str,caller:CacheCaller,args:&Map<String,Value>)->Option<Self>{
        if server.is_empty() || tool.is_empty() || descriptor.len()!=64 {return None;}
        let mut canonical=Value::Object(args.clone());
        // Preserve JSON scalar types, number representations, strings and
        // array order. Only object member order is insignificant.
        canonical.sort_all_objects();
        let args=serde_json::to_vec(&canonical).ok()?;
        if args.len()>MAX_BYTES{return None;}
        let mut hash=Sha256::new();
        hash.update(b"agent-bridge.extension.cache.v2\0");
        for field in [server.as_bytes(),tool.as_bytes(),descriptor.as_bytes(),
            caller.token_hash.as_slice(), &[caller.profile], args.as_slice()]{
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        Some(Self(hash.finalize().into()))
    }
}

struct Entry { bytes:Box<[u8]>, expires:Instant, last_used:u64 }

#[derive(Default)]
struct State {
    generation:u64,
    disabled:bool,
    entries:HashMap<Key,Entry>,
    clock:u64,
}
impl State {
    fn tick(&mut self)->u64{
        self.clock=self.clock.saturating_add(1);
        self.clock
    }
    fn prune(&mut self,now:Instant){self.entries.retain(|_,entry|entry.expires>now);}
}

/// The generation and entries are protected by one lock. Invalidation
/// fences *every* earlier admission, even if the original profile or
/// registry fingerprint is later restored.
#[derive(Default)]
pub(crate) struct ResultCache(Mutex<State>);
impl ResultCache {
    pub(crate) fn invalidate(&self){
        let mut s=self.0.lock().unwrap_or_else(|p|p.into_inner());
        s.entries.clear();
        if let Some(next)=s.generation.checked_add(1){s.generation=next;}
        else{s.disabled=true;}
    }
    pub(crate) fn request(self:&Arc<Self>,caller:CacheCaller)->Option<CacheRequest>{
        let s=self.0.lock().ok()?;
        if s.disabled{return None;}
        Some(CacheRequest{cache:self.clone(),generation:s.generation,caller})
    }
}

#[derive(Clone)]
pub struct CacheRequest {
    cache:Arc<ResultCache>,
    generation:u64,
    caller:CacheCaller,
}
impl CacheRequest {
    /// Revalidate the early HTTP observation at the actual live registry gate.
    pub(crate) fn claim(&self,cache:&Arc<ResultCache>,profile:u8)->Option<Self>{
        if !Arc::ptr_eq(cache,&self.cache) || profile!=self.caller.profile{return None;}
        let s=cache.0.lock().ok()?;
        (!s.disabled && s.generation==self.generation).then(||self.clone())
    }
    pub(crate) fn tool(&self,server:&str,tool:&str,descriptor:&str,args:&Map<String,Value>,policy:Policy)
        ->Option<Flight>{
        Some(Flight{cache:self.cache.clone(),generation:self.generation,
            key:Key::new(server,tool,descriptor,self.caller,args)?,
            ttl:Duration::from_secs(policy.ttl_seconds)})
    }
}
pub(crate) struct Flight {
    cache:Arc<ResultCache>,
    generation:u64,
    key:Key,
    ttl:Duration,
}
impl Flight {
    fn current(&self,s:&State,cancel:Option<&CancellationToken>)->bool{
        !s.disabled && s.generation==self.generation &&
            !cancel.is_some_and(CancellationToken::is_cancelled)
    }
    pub(crate) fn get(&self,now:Instant,cancel:Option<&CancellationToken>)->Option<Value>{
        let mut s=self.cache.0.lock().ok()?;
        if !self.current(&s,cancel){return None;}
        s.prune(now);
        let seq=s.tick();
        let entry=s.entries.get_mut(&self.key)?;
        entry.last_used=seq;
        serde_json::from_slice(&entry.bytes).ok()
    }

    /// Only Registry's final result policy boundary may publish here.
    /// This function is deliberately private to the extension crate.
    pub(crate) fn publish_filtered(self,value:&Value,now:Instant,cancel:Option<&CancellationToken>){
        let Some(result)=value.as_object() else{return;};
        if !result.get("content").is_some_and(Value::is_array) ||
            result.get("isError").is_some_and(|v|v!=&Value::Bool(false)) ||
            result.contains_key("error") || result.contains_key("is_error") ||
            self.ttl.is_zero() || self.ttl>Duration::from_secs(MAX_TTL) {return;}
        let Ok(bytes)=serde_json::to_vec(value) else{return;};
        if bytes.len()>MAX_BYTES{return;}
        let Some(expires)=now.checked_add(self.ttl) else{return;};
        let Ok(mut s)=self.cache.0.lock() else{return;};
        if !self.current(&s,cancel){return;}
        s.prune(now);
        if !s.entries.contains_key(&self.key) && s.entries.len()>=MAX_ENTRIES{
            if let Some(victim)=s.entries.iter().min_by_key(|(_,e)|e.last_used).map(|(k,_)|*k){
                s.entries.remove(&victim);
            }
        }
        let seq=s.tick();
        s.entries.insert(self.key,Entry{bytes:bytes.into_boxed_slice(),expires,last_used:seq});
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn caller(n:u8,p:u8)->CacheCaller{CacheCaller::authenticated([n;32],p).unwrap()}
    fn args(value:Value)->Map<String,Value>{value.as_object().unwrap().clone()}
    fn flight(cache:&Arc<ResultCache>,caller:CacheCaller,value:Value)->Flight{
        cache.request(caller).unwrap().tool("srv","search",&"a".repeat(64),&args(value),
            Policy{read_only:true,ttl_seconds:10}).unwrap()
    }
    fn output()->Value{json!({"content":[{"type":"text","text":"filtered"}],"isError":false})}

    #[test]
    fn cache_key_preserves_scalar_values_and_exact_partitions(){
        let cache=Arc::new(ResultCache::default());
        let k=|c,v|flight(&cache,c,v).key;
        assert!(k(caller(1,0),json!({"a":1,"b":{"x":2,"y":3}}))==
            k(caller(1,0),json!({"b":{"y":3,"x":2},"a":1})));
        for (a,b) in [(json!({"a":0}),json!({"a":0.0})),
            (json!({"a":0.0}),json!({"a":-0.0})),
            (json!({"a":" x"}),json!({"a":"x"})),
            (json!({"a":[1,2]}),json!({"a":[2,1]}))]{
            assert!(k(caller(1,0),a)!=k(caller(1,0),b));
        }
        assert!(k(caller(1,0),json!({}))!=k(caller(2,0),json!({})));
        assert!(k(caller(1,0),json!({}))!=k(caller(1,1),json!({})));
        let a=args(json!({}));
        assert!(Key::new("a","bc",&"a".repeat(64),caller(1,0),&a)!=
            Key::new("ab","c",&"a".repeat(64),caller(1,0),&a));
    }
    #[test]
    fn cache_request_cannot_cross_registry_or_profile_or_return_to_old_epoch(){
        let first=Arc::new(ResultCache::default());
        let second=Arc::new(ResultCache::default());
        let old=first.request(caller(1,2)).unwrap();
        assert!(old.claim(&first,2).is_some());
        assert!(old.claim(&second,2).is_none());
        assert!(old.claim(&first,3).is_none());
        first.invalidate();
        first.invalidate();
        assert!(old.claim(&first,2).is_none());
        assert!(first.request(caller(1,2)).unwrap().claim(&first,2).is_some());
    }

    #[test]
    fn cache_fences_in_flight_and_expiry(){
        let cache=Arc::new(ResultCache::default());
        let at=Instant::now();
        let f=||flight(&cache,caller(1,0),json!({}));
        f().publish_filtered(&output(),at,None);
        assert_eq!(f().get(at,None),Some(output()));
        assert_eq!(f().get(at+Duration::from_secs(10),None),None);
        let prior=f();
        cache.invalidate();
        prior.publish_filtered(&output(),at,None);
        assert!(f().get(at,None).is_none());
        let cancelled=CancellationToken::new();cancelled.cancel();
        f().publish_filtered(&output(),at,Some(&cancelled));
        assert!(f().get(at,None).is_none());
    }
    #[test]
    fn cache_bounded_successes_only(){
        let cache=Arc::new(ResultCache::default());let at=Instant::now();
        let f=||flight(&cache,caller(1,0),json!({}));
        for v in [json!({"isError":true,"content":[]}),json!({"content":[],"isError":"false"}),
            json!({"content":[],"error":null}),Value::Null,json!({"content":"bad"}),
            json!({"content":[{"type":"text","text":"x".repeat(MAX_BYTES)}]})]{
            f().publish_filtered(&v,at,None);assert!(f().get(at,None).is_none());
        }
        for i in 0..MAX_ENTRIES+1{
            flight(&cache,caller(1,0),json!({"i":i})).publish_filtered(&output(),at,None);
        }
        assert_eq!(cache.0.lock().unwrap().entries.len(),MAX_ENTRIES);
        assert!(flight(&cache,caller(1,0),json!({"i":0})).get(at,None).is_none());
    }
    #[test]
    fn cache_policy_requires_explicit_local_rule_and_safe_annotations(){
        let good=json!({"annotations":{"readOnlyHint":true,"destructiveHint":false}});
        let p=Policy{read_only:true,ttl_seconds:30};
        assert!(p.valid(&good));
        assert!(p.valid(&json!({"annotations":{"readOnlyHint":true}})));
        for bad in [json!({}),json!({"annotations":{"readOnlyHint":true,"destructiveHint":true}}),
            json!({"annotations":{"readOnlyHint":"true"}}),json!({"annotations":{"readOnlyHint":true,"destructiveHint":"false"}})]{
            assert!(!p.valid(&bad));
        }
        assert!(!(Policy{read_only:false,..p}).valid(&good));
        assert!(!(Policy{ttl_seconds:301,..p}).valid(&good));
    }
}