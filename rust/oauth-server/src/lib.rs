// Copyright 2026 Agent Bridge contributors. Licensed under Apache-2.0.
//! The existing Agent Bridge / Gemini OAuth 2.1 protocol, with no listener,
//! process execution, proxy, remote owner-approval endpoint or credential import.
//!
//! Integrate OAuthServer::handle_http with an orchestrator-owned public route.
//! An authorized MCP route yields a verified AuthorizedIdentity, NOT an HTTP
//! forwarding operation or an Agent Bridge actor-context capability.
//!
//! The local CLI alone may open LocalOwner and present an exact pending request
//! to its human operator. Neither local enrollment nor owner approval exists
//! among the public OAuth HTTP routes. Never expose LocalOwner via the network.

mod model;
mod platform;
mod store;
mod http;

#[cfg(test)]
mod capability_tests;

pub use agent_bridge_oauth_compat::{Audience, CapabilityIdentity};
pub use http::{HttpAction, HttpRequest, HttpResponse, VerifiedOAuthClient};
pub use model::ConnectorClient;

use model::{
    Binding, Client, Code, Pending, Policy, ACCESS_TTL_MS, APPROVAL_TTL_MS,
    CLIENT_MAX, CODE_TTL_MS, GRANT_TTL_MS, PENDING_MAX, PROVISIONAL_MAX, SCOPE,
    callback_family, digest, equal, expiry_ms, now_ms, random_token, token_shape,
    verifier_shape,
};
use serde_json::{json, Map, Value};
use std::{collections::{BTreeMap, HashMap}, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid OAuth configuration: {0}")]
    Invalid(&'static str),
    #[error("incompatible historical OAuth data: {0}")]
    Incompatible(&'static str),
    #[error("private OAuth filesystem refused: {0}")]
    PrivateState(&'static str),
    #[error("OAuth state is owned by another or uncertain instance")]
    Busy,
    #[error("OAuth result uncertain: {0}")]
    Uncertain(&'static str),
    #[error("OAuth request rejected: {code}")]
    Bad { code: &'static str, status: u16 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
impl OAuthError {
    pub(crate) fn bad(code:&'static str,status:u16)->Self{Self::Bad{code,status}}
}
pub type Result<T>=std::result::Result<T,OAuthError>;

#[derive(Clone)]
pub struct OAuthConfig {
    pub state_dir:PathBuf,
    /// HTTPS origin independently qualified by the orchestrator. Never trust
    /// a resource URL supplied in a token, a stored grant or a remote request.
    pub public_origin:String,
    pub audience:Audience,
}
impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.debug_struct("OAuthConfig").field("audience",&self.audience)
            .field("state_dir",&"[redacted]").field("public_origin",&"[redacted]").finish()
    }
}

/// This is a verified local ChatGPT/Gemini MCP OAuth client identity. It is not a mission
/// membership, workspace permission, agent_context_handle, or login session.
#[derive(Clone,PartialEq,Eq)]
pub struct AuthorizedIdentity{
    pub client_id:String,
    pub provider:ConnectorClient,
    pub audience:Audience,
    pub scope:String,
    pub resource:String,
    pub capability:CapabilityIdentity,
}
impl std::fmt::Debug for AuthorizedIdentity{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.debug_struct("AuthorizedIdentity").field("audience",&self.audience)
            .field("scope",&self.scope).finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) enum AuthorizationFlow{
    PendingLocalApproval(String),
    RedirectToGoogle(String),
}

/// Authoritative single-writer OAuth core. It never reads config.json or a
/// control credential: public origin and audience arrive via OAuthConfig.
/// It never infers workstation authority from a missions grant.
pub struct OAuthServer{
    pub(crate) policy:Policy,
    // Locally qualified router identity, immutable for this service lifetime.
    capability:CapabilityIdentity,
    pub(crate) store:store::Store,
    pub(crate) data:Value,
    pub(crate) pending:HashMap<String,Pending>,
    pub(crate) codes:HashMap<String,Code>,
    pub(crate) provisional:HashMap<String,Client>,
    pub(crate) last_registration:Option<i64>,
    pub(crate) uncertain:bool,
    pub(crate) rate_window_start:i64,
    pub(crate) public_requests:u32,
    pub(crate) private_requests:u32,
}
impl OAuthServer {
    /// Opens only a pre-existing, owner-private state directory; refuses a
    /// concurrent Node running.lock, a second Rust owner, unknown schema,
    /// ambiguous JSON, resource drift or revocation extensions.
    pub fn open(options:OAuthConfig)->Result<Self>{
        Self::open_with_capability(options,CapabilityIdentity::Legacy)
    }

    /// Only the local orchestrator may supply an identity whose exact router
    /// and physical manifest have already been qualified. Remote input cannot
    /// select or replace it. Historical grants remain Legacy in this instance.
    pub fn open_with_capability(options:OAuthConfig,capability:CapabilityIdentity)->Result<Self>{
        if !capability.validate() || (options.audience!=Audience::Workstation && !capability.is_legacy()) {
            return Err(OAuthError::Invalid("invalid_local_capability"));
        }
        let policy=Policy::new(&options.public_origin,options.audience)?;
        let now=now_ms()?;
        let (store,data)=store::Store::open(&options.state_dir,&policy,now)?;
        Ok(Self{policy,capability,store,data,pending:HashMap::new(),codes:HashMap::new(),
            provisional:HashMap::new(),last_registration:None,uncertain:false,
            rate_window_start:now,public_requests:0,private_requests:0})
    }

    fn grant_capability(&self,grant:&Value)->Option<CapabilityIdentity>{
        let identity=CapabilityIdentity::from_marker(grant.get("capability")).ok()?;
        (identity.is_legacy() || identity==self.capability).then_some(identity)
    }

    fn ensure_healthy(&self)->Result<()>{
        if self.uncertain{
            return Err(OAuthError::Uncertain("oauth_write_outcome_requires_reconciliation"));
        }
        Ok(())
    }

    pub(crate) fn count_request(&mut self,is_private:bool,now:i64)->Result<()>{
        self.ensure_healthy()?;
        if now<self.rate_window_start{
            return Err(OAuthError::Uncertain("system_clock_moved_backwards"));
        }
        if now-self.rate_window_start>=60_000{
            self.rate_window_start=now;
            self.public_requests=0;
            self.private_requests=0;
        }
        let (counter,limit)=if is_private{
            (&mut self.private_requests,1000)
        }else{
            (&mut self.public_requests,240)
        };
        if *counter>=limit{
            return Err(OAuthError::bad("request_limit",429));
        }
        *counter+=1;
        Ok(())
    }

    /// Audience-specific bearer validation, to be called again by the
    /// orchestrator immediately before dispatching each accepted MCP request.
    /// No mutations, no replay, no forwarding and no cached authorization.
    /// Seal locally qualified public authority metadata under this exclusive
    /// OAuth owner. This never changes registrations, tokens or legacy scope.
    pub fn bind_capability_manifest(&self, canonical_manifest: &[u8]) -> Result<()> {
        use sha2::{Digest,Sha256};
        let CapabilityIdentity::UnifiedV1 {manifest_sha256,catalogue_sha256,policy_version}=&self.capability
            else {return Err(OAuthError::Invalid("legacy_has_no_unified_manifest"));};
        if canonical_manifest.len()>256*1024 {
            return Err(OAuthError::PrivateState("unified_manifest_size_limit"));
        }
        let actual:String=Sha256::digest(canonical_manifest).iter().map(|byte|format!("{byte:02x}")).collect();
        if &actual!=manifest_sha256 {return Err(OAuthError::Invalid("unified_manifest_digest_mismatch"));}
        let manifest:Value=serde_json::from_slice(canonical_manifest)?;
        if !manifest.is_object() || manifest.get("policy_version").and_then(Value::as_u64)!=Some(*policy_version as u64)
            || manifest.get("catalogue_sha256").and_then(Value::as_str)!=Some(catalogue_sha256.as_str())
            || serde_json::to_vec(&manifest)?!=canonical_manifest
        {return Err(OAuthError::Invalid("unified_manifest_contract_mismatch"));}
        self.store.bind_manifest(manifest_sha256,canonical_manifest)
    }

    pub fn authorize_mcp(&self,authorization:Option<&str>)->Result<AuthorizedIdentity>{
        self.authorize_mcp_at(authorization,now_ms()?)
    }

    fn authorize_mcp_at(&self,authorization:Option<&str>,now:i64)->Result<AuthorizedIdentity>{
        self.ensure_healthy()?;
        let bearer=authorization.and_then(|s|s.strip_prefix("Bearer "))
            .filter(|s|token_shape(s)).ok_or(OAuthError::bad("invalid_token",401))?;
        let hash=digest(bearer);
        let access=collection(&self.data,"access")?.get(&hash)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        if model::revoked_extension(access)
            || access.get("expires").and_then(Value::as_i64).is_none_or(|until|until<=now)
        {return Err(OAuthError::bad("invalid_token",401));}
        let grant_id=access.get("grant").and_then(Value::as_str)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        let grant=collection(&self.data,"grants")?.get(grant_id)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        if model::revoked_extension(grant)
            || grant.get("expires").and_then(Value::as_i64).is_none_or(|until|until<=now)
            || grant.get("resource").and_then(Value::as_str)!=Some(self.policy.resource.as_str())
            || grant.get("scope").and_then(Value::as_str)!=Some(SCOPE)
            || !self.policy.audience_valid(grant.get("audience"))
        {return Err(OAuthError::bad("invalid_token",401));}
        let capability=self.grant_capability(grant)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        let client_id=grant.get("clientId").and_then(Value::as_str)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        // This is an issued-client check, NOT a provisional or request ID.
        let client=self.persisted_client(client_id)
            .ok_or(OAuthError::bad("invalid_token",401))?;
        Ok(AuthorizedIdentity{client_id:client_id.to_owned(),provider:client.provider,
            audience:self.policy.audience,scope:SCOPE.into(),
            resource:self.policy.resource.clone(),capability})
    }

    pub(crate) fn persisted_client(&self,id:&str)->Option<Client>{
        collection(&self.data,"clients").ok()?.get(id).and_then(Client::from_json)
            .filter(|client|client.provider.matches_id(id))
    }
    fn registered_or_provisional(&self,id:&str,now:i64)->Option<Client>{
        self.persisted_client(id).or_else(||self.provisional.get(id)
            .filter(|c|c.expires>now).cloned())
    }
    fn authenticate_client(&self,auth:Option<&str>,input:&BTreeMap<String,String>)
        ->Result<String>
    {
        let (id,secret,method)=if let Some(header)=auth{
            if input.contains_key("client_id") || input.contains_key("client_secret"){
                return Err(OAuthError::bad("invalid_client",401));
            }
            let (id,secret)=model::basic_client(header)
                .ok_or(OAuthError::bad("invalid_client",401))?;
            (id,secret,"client_secret_basic")
        }else{
            (input.get("client_id").cloned().unwrap_or_default(),
            input.get("client_secret").cloned().unwrap_or_default(),
            "client_secret_post")
        };
        if id.is_empty()||secret.is_empty()||secret.len()>4096{
            return Err(OAuthError::bad("invalid_client",401));
        }
        let client=self.persisted_client(&id)
            .ok_or(OAuthError::bad("invalid_client",401))?;
        if client.method!=method || !equal(&digest(&secret),&client.secret_hash){
            return Err(OAuthError::bad("invalid_client",401));
        }
        Ok(id)
    }

    fn persist<F,T>(&mut self,change:F)->Result<T>
    where F:FnOnce(&mut Value)->Result<T>{
        self.ensure_healthy()?;
        let mut next=self.data.clone();
        let result=change(&mut next)?;
        // A failed fsync/rename may have committed to disk already.
        // A poisoned instance can no longer admit any bearer or grant action.
        self.uncertain=true;
        self.store.save(&next)?;
        self.data=next;
        self.uncertain=false;
        Ok(result)
    }

    // In-memory codes and pending authorizations are never recovered from a
    // prior process incarnation. Persisted legacy grants/access are retained.
    fn prune(&mut self,now:i64)->Result<()>{
        self.codes.retain(|_,v|v.expires>now);
        self.provisional.retain(|_,v|v.expires>now);
        let expired=self.pending.iter()
            .filter(|(_,v)|v.expires<=now)
            .map(|(hash,p)|(hash.clone(),p.id.clone())).collect::<Vec<_>>();
        for (hash,id) in expired{
            self.uncertain=true;
            self.store.remove_request(&id)?;
            self.pending.remove(&hash);
            self.uncertain=false;
        }
        let mut next=self.data.clone();
        let grants=collection_mut(&mut next,"grants")?;
        let before=grants.len();
        grants.retain(|_,g|g.get("expires").and_then(Value::as_i64).is_some_and(|v|v>now));
        let grants_changed=grants.len()!=before;
        let grant_ids:std::collections::HashSet<String>=grants.keys().cloned().collect();
        let access=collection_mut(&mut next,"access")?;
        let before=access.len();
        access.retain(|_,a|a.get("expires").and_then(Value::as_i64).is_some_and(|v|v>now)
            && a.get("grant").and_then(Value::as_str)
                .is_some_and(|g|grant_ids.contains(g)));
        if grants_changed||access.len()!=before{
            self.uncertain=true;
            self.store.save(&next)?;
            self.data=next;
            self.uncertain=false;
        }
        Ok(())
    }

    pub(crate) fn register(&mut self,input:Value,now:i64)->Result<Value>{
        if !self.store.enabled_enrollment(now)?{
            return Err(OAuthError::bad("local_enrollment_required",403))
        }
        if self.last_registration.is_some_and(|t|now-t<1000){
            return Err(OAuthError::bad("registration_limit",429));
        }
        let obj=input.as_object().ok_or(OAuthError::bad("invalid_client_metadata",400))?;
        let redirects=obj.get("redirect_uris")
            .and_then(Value::as_array).ok_or(OAuthError::bad("invalid_redirect_uri",400))?;
        if redirects.is_empty()||redirects.len()>6 {
            return Err(OAuthError::bad("invalid_redirect_uri",400));
        }
        // DCR is allowed only during local enrollment, and callback families
        // are from official ChatGPT/Gemini domains. One registration cannot
        // mix these clients. The COMPLETE exact redirect URI is stored under
        // its generated client ID, and is required again at authorize and
        // token exchange; never trust an arbitrary remotely supplied URL.
        let first=redirects[0].as_str()
            .and_then(|url|callback_family(url,true))
            .ok_or(OAuthError::bad("invalid_redirect_uri",400))?;
        if redirects.iter().any(|v|v.as_str()
            .is_none_or(|url|!first.callback(url,true)))
        {return Err(OAuthError::bad("invalid_redirect_uri",400));}
        let method=match obj.get("token_endpoint_auth_method"){
            None=>"client_secret_basic",
            Some(Value::String(s)) if s=="client_secret_basic"||s=="client_secret_post"=>s,
            _=>return Err(OAuthError::bad("confidential_client_required",400)),
        };
        if let Some(types)=obj.get("grant_types"){
            if types.as_array().is_none_or(|v|v.iter().any(|x|
                !matches!(x.as_str(),Some("authorization_code"|"refresh_token"))))
            {return Err(OAuthError::bad("invalid_client_metadata",400));}
        }
        if let Some(types)=obj.get("response_types"){
            if types.as_array().is_none_or(|v|v.iter().any(|x|x.as_str()!=Some("code"))){
                return Err(OAuthError::bad("invalid_client_metadata",400));
            }
        }
        if self.provisional.len()>=PROVISIONAL_MAX
            || collection(&self.data,"clients")?.len()>=CLIENT_MAX
        {return Err(OAuthError::bad("registration_limit",429));}
        let client_id=format!("{}{}",first.id_prefix(),random_token()?);
        let client_secret=random_token()?;
        let redirects:Vec<String>=redirects.iter()
            .filter_map(|v|v.as_str().map(str::to_owned)).collect();
        let client=Client{
            redirects:redirects.clone(),provider:first,method:method.to_owned(),
            secret_hash:digest(&client_secret),created:now,expires:expiry_ms(now,APPROVAL_TTL_MS)?,
        };
        self.provisional.insert(client_id.clone(),client);
        self.last_registration=Some(now);
        Ok(json!({
            "client_id":client_id,"client_secret":client_secret,
            "client_secret_expires_at":0,"client_id_issued_at":now/1000,
            "redirect_uris":redirects,
            "token_endpoint_auth_method":method,
            "grant_types":["authorization_code","refresh_token"],
            "response_types":["code"],"scope":SCOPE
        }))
    }

    pub(crate) fn authorize(&mut self,input:&BTreeMap<String,String>,now:i64)
        ->Result<AuthorizationFlow>
    {
        let required=|key:&str|input.get(key).map(String::as_str).unwrap_or("");
        let client_id=required("client_id");
        let redirect=required("redirect_uri");
        let client=self.registered_or_provisional(client_id,now)
            .ok_or(OAuthError::bad("invalid_client_or_redirect",400))?;
        if !client.provider.matches_id(client_id)
            || !client.redirects.iter().any(|s|s==redirect)
            || !client.provider.callback(redirect,false)
        {
            return Err(OAuthError::bad("invalid_client_or_redirect",400))
        }
        let challenge=required("code_challenge");
        if required("response_type")!="code" || required("code_challenge_method")!="S256"
            || !token_shape(challenge)
        {return Err(OAuthError::bad("pkce_required",400));}
        let state=required("state");
        if state.is_empty() || state.len()>2048{return Err(OAuthError::bad("state_required",400))}
        if input.get("scope").is_some_and(|s|s!=SCOPE){
            return Err(OAuthError::bad("invalid_scope",400))
        }
        if input.get("resource").is_some_and(|s|s!=&self.policy.resource){
            return Err(OAuthError::bad("invalid_target",400))
        }
        let binding=Binding{
            client_id:client_id.to_owned(),redirect:redirect.to_owned(),
            challenge:challenge.to_owned(),state:state.to_owned(),
            resource:self.policy.resource.clone(),scope:SCOPE.into(),
            capability:self.capability.clone(),
        };
        let key=binding.hash()?;
        let pending=match self.pending.get(&key){
            Some(existing)=>existing.clone(),
            None=>{
                if self.pending.len()>=PENDING_MAX{
                    return Err(OAuthError::bad("authorization_limit",429))
                }
                let pending=Pending{binding:binding.clone(),id:random_token()?,
                    expires:expiry_ms(now,APPROVAL_TTL_MS)?};
                self.store.requested(&store::ApprovalRequest{
                    id:pending.id.clone(),client_id:client_id.to_owned(),
                    redirect:redirect.to_owned(),scope:SCOPE.into(),
                    resource:self.policy.resource.clone(),expires:pending.expires,
                    binding_hash:key.clone(),audience:self.policy.audience_str().into(),
                    capability:pending.binding.capability.clone(),
                })?;
                self.pending.insert(key.clone(),pending.clone());
                pending
            }
        };
        let expected=self.store.request(&pending.id)?
            .ok_or(OAuthError::Uncertain("pending_request_disappeared"))?;
        if expected.id!=pending.id || expected.binding_hash!=key
            || expected.expires!=pending.expires
            || expected.client_id!=client_id || expected.redirect!=redirect
            || expected.resource!=self.policy.resource || expected.scope!=SCOPE
            || expected.audience!=self.policy.audience_str()
            || expected.capability!=pending.binding.capability
        {return Err(OAuthError::Uncertain("pending_request_changed"));}
        let Some(approval)=self.store.approved(&pending.id)? else{
            return Ok(AuthorizationFlow::PendingLocalApproval(pending.id))
        };
        if approval.binding_hash!=key || approval.expires!=pending.expires
            || approval.expires<=now || approval.audience!=self.policy.audience_str()
            || approval.capability!=pending.binding.capability
        {return Err(OAuthError::bad("approval_invalid",403));}
        if self.persisted_client(client_id).is_none(){
            if collection(&self.data,"clients")?.len()>=CLIENT_MAX{
                return Err(OAuthError::bad("registration_limit",429))
            }
            let client_data=client.json();
            let id=client_id.to_owned();
            self.persist(|data|{
                collection_mut(data,"clients")?.insert(id,client_data);
                Ok(())
            })?;
            self.provisional.remove(client_id);
        }
        // The local approval is consumed once. A lost reply must be resolved
        // by a NEW approval; a previous code or request is never resurrected.
        self.uncertain=true;
        self.store.remove_request(&pending.id)?;
        self.pending.remove(&key);
        self.uncertain=false;
        let code=random_token()?;
        self.codes.insert(digest(&code),Code{
            binding:pending.binding,expires:expiry_ms(now,CODE_TTL_MS)?
        });
        let mut callback=url::Url::parse(redirect)
            .map_err(|_|OAuthError::Uncertain("client_callback_changed"))?;
        callback.query_pairs_mut()
            .append_pair("code",&code)
            .append_pair("state",state)
            .append_pair("iss",&self.policy.base);
        Ok(AuthorizationFlow::RedirectToGoogle(callback.to_string()))
    }

    pub(crate) fn exchange(
        &mut self,input:&BTreeMap<String,String>,authorization:Option<&str>,now:i64
    )->Result<Value>{
        let client_id=self.authenticate_client(authorization,input)?;
        if input.get("resource").is_some_and(|s|s!=&self.policy.resource){
            return Err(OAuthError::bad("invalid_target",400));
        }
        if input.get("scope").is_some_and(|s|s!=SCOPE){
            return Err(OAuthError::bad("invalid_scope",400));
        }
        match input.get("grant_type").map(String::as_str){
            Some("authorization_code")=>{
                let code=input.get("code").map(String::as_str).unwrap_or("");
                let verifier=input.get("code_verifier").map(String::as_str).unwrap_or("");
                let saved=self.codes.get(&digest(code))
                    .filter(|code|code.expires>now
                        && code.binding.client_id==client_id
                        && input.get("redirect_uri").is_some_and(|v|v==&code.binding.redirect)
                        && verifier_shape(verifier)
                        && equal(&digest(verifier),&code.binding.challenge))
                    .cloned().ok_or(OAuthError::bad("invalid_grant",400))?;
                // The code is spent BEFORE any uncertain disk mutation.
                self.codes.remove(&digest(code));
                if saved.binding.resource!=self.policy.resource||saved.binding.scope!=SCOPE
                    || !(saved.binding.capability.is_legacy() || saved.binding.capability==self.capability) {
                    return Err(OAuthError::bad("invalid_grant",400))
                }
                let grant_id=random_token()?;
                let refresh=random_token()?;
                let access=random_token()?;
                let grant_expires=expiry_ms(now,GRANT_TTL_MS)?;
                let access_expires=expiry_ms(now,ACCESS_TTL_MS)?;
                let mut grant=match self.policy.audience{
                    Audience::Missions=>json!({
                        "clientId":client_id,"resource":self.policy.resource,
                        "scope":SCOPE,"refreshHash":digest(&refresh),"expires":grant_expires
                    }),
                    Audience::Workstation=>json!({
                        "clientId":client_id,"resource":self.policy.resource,
                        "scope":SCOPE,"audience":"workstation",
                        "refreshHash":digest(&refresh),"expires":grant_expires
                    })
                };
                if !saved.binding.capability.is_legacy() {
                    grant.as_object_mut().ok_or(OAuthError::Uncertain("grant_shape_invalid"))?
                        .insert("capability".into(),serde_json::to_value(&saved.binding.capability)?);
                }
                self.persist(|data|{
                    collection_mut(data,"grants")?.insert(grant_id.clone(),grant);
                    collection_mut(data,"access")?.insert(digest(&access),
                        json!({"grant":grant_id,"expires":access_expires}));
                    Ok(())
                })?;
                Ok(token_response(access,refresh))
            }
            Some("refresh_token")=>{
                let refresh=input.get("refresh_token").map(String::as_str).unwrap_or("");
                if !token_shape(refresh){return Err(OAuthError::bad("invalid_grant",400));}
                let refresh_digest=digest(refresh);
                let pair=collection(&self.data,"grants")?.iter().find_map(|(id,g)|{
                    (g.get("clientId").and_then(Value::as_str)==Some(client_id.as_str())
                        && g.get("resource").and_then(Value::as_str)
                            ==Some(self.policy.resource.as_str())
                        && g.get("scope").and_then(Value::as_str)==Some(SCOPE)
                        && self.policy.audience_valid(g.get("audience"))
                        && !model::revoked_extension(g)
                        && self.grant_capability(g).is_some()
                        && g.get("expires").and_then(Value::as_i64)
                            .is_some_and(|expires|expires>now)
                        && g.get("refreshHash").and_then(Value::as_str)
                            .is_some_and(|v|equal(v,&refresh_digest)))
                        .then(||id.clone())
                }).ok_or(OAuthError::bad("invalid_grant",400))?;
                let access=random_token()?;
                let grant_expires=expiry_ms(now,GRANT_TTL_MS)?;
                let access_expires=expiry_ms(now,ACCESS_TTL_MS)?;
                self.persist(|data|{
                    let grant=collection_mut(data,"grants")?.get_mut(&pair)
                        .ok_or(OAuthError::Uncertain("refresh_grant_disappeared"))?;
                    grant.as_object_mut()
                        .ok_or(OAuthError::Incompatible("malformed_grant"))?
                        .insert("expires".into(),json!(grant_expires));
                    collection_mut(data,"access")?.insert(digest(&access),
                        json!({"grant":pair,"expires":access_expires}));
                    Ok(())
                })?;
                // The historical refresh token does NOT rotate.
                Ok(token_response(access,refresh.to_owned()))
            }
            _=>Err(OAuthError::bad("unsupported_grant_type",400)),
        }
    }

    pub(crate) fn revoke(
        &mut self,input:&BTreeMap<String,String>,authorization:Option<&str>,now:i64
    )->Result<Value>{
        let client_id=self.authenticate_client(authorization,input)?;
        if input.get("resource").is_some_and(|s|s!=&self.policy.resource){
            return Err(OAuthError::bad("invalid_target",400));
        }
        if input.get("scope").is_some_and(|s|s!=SCOPE){
            return Err(OAuthError::bad("invalid_scope",400));
        }
        let digest_value=digest(input.get("token").map(String::as_str).unwrap_or(""));
        let access_grant=collection(&self.data,"access")?.get(&digest_value)
            .and_then(|v|v.get("grant")).and_then(Value::as_str).map(str::to_owned);
        let revoked=collection(&self.data,"grants")?.iter().filter_map(|(id,g)|{
            if g.get("clientId").and_then(Value::as_str)!=Some(client_id.as_str()){return None}
            let refresh_match=g.get("refreshHash").and_then(Value::as_str)
                .is_some_and(|h|equal(h,&digest_value));
            (refresh_match||access_grant.as_deref()==Some(id)).then(||id.clone())
        }).collect::<Vec<_>>();
        if !revoked.is_empty(){
            let set=revoked.into_iter().collect::<std::collections::HashSet<_>>();
            self.persist(|data|{
                collection_mut(data,"grants")?.retain(|id,_|!set.contains(id));
                collection_mut(data,"access")?.retain(|_,a|
                    a.get("grant").and_then(Value::as_str).is_none_or(|id|!set.contains(id)));
                Ok(())
            })?;
        }
        self.prune(now)?;
        Ok(json!({}))
    }
}
fn token_response(access:String,refresh:String)->Value{
    json!({"access_token":access,"token_type":"Bearer","expires_in":3600,
        "refresh_token":refresh,"scope":SCOPE})
}
fn collection<'a>(source:&'a Value,key:&str)->Result<&'a Map<String,Value>>{
    source.get(key).and_then(Value::as_object)
        .ok_or(OAuthError::Incompatible("historical_collection_missing"))
}
fn collection_mut<'a>(source:&'a mut Value,key:&str)->Result<&'a mut Map<String,Value>>{
    source.get_mut(key).and_then(Value::as_object_mut)
        .ok_or(OAuthError::Incompatible("historical_collection_missing"))
}

/// Information the local operator is explicitly approving. Contract digests
/// are public review data; no bearer, refresh or client secret is included.
#[derive(Clone)]
pub struct LocalApprovalRequest{
    pub id:String,
    pub client_id:String,
    pub redirect_uri:String,
    pub resource:String,
    pub scope:String,
    pub expires_epoch_ms:i64,
    pub audience:Audience,
    pub capability:CapabilityIdentity,
}
impl std::fmt::Debug for LocalApprovalRequest{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.debug_struct("LocalApprovalRequest")
            .field("audience",&self.audience).field("expires_epoch_ms",&self.expires_epoch_ms)
            .finish_non_exhaustive()
    }
}

/// File-based owner controller for an explicitly LOCAL CLI. This has no public
/// HTTP entry point and never opens OAuth token storage or credentials.
pub struct LocalOwner{
    files:store::LocalFiles,
    policy:Policy,
}
impl LocalOwner{
    pub fn open(config:OAuthConfig)->Result<Self>{
        let policy=Policy::new(&config.public_origin,config.audience)?;
        let files=store::LocalFiles::open(&config.state_dir,&policy)?;
        Ok(Self{files,policy})
    }
    /// A new remote DCR window is NOT consent to an authorization grant.
    /// The CLI must obtain affirmative local human permission before passing
    /// a confirmation closure that returns true.
    pub fn enable_enrollment(
        &self,confirm_local_owner:impl FnOnce()->bool
    )->Result<i64>{
        if !confirm_local_owner(){
            return Err(OAuthError::bad("local_owner_consent_required",403));
        }
        let until=expiry_ms(now_ms()?,APPROVAL_TTL_MS)?;
        self.files.enroll(until)?;
        Ok(until)
    }
    pub fn pending_requests(&self)->Result<Vec<LocalApprovalRequest>>{
        let now=now_ms()?;
        let mut out=Vec::new();
        for id in self.files.request_list()?{
            if let Some(doc)=self.files.request(&id)?{
                if let Ok(details)=self.validate_local_request(&doc,now){
                    out.push(details);
                }
            }
        }
        Ok(out)
    }
    /// Each exact request must be displayed and approved locally. Never pass
    /// a blanket auto-approval closure from a network request handler.
    pub fn approve_request(
        &self,id:&str,confirm_local_owner:impl FnOnce(&LocalApprovalRequest)->bool
    )->Result<()>{
        let now=now_ms()?;
        let doc=self.files.request(id)?
            .ok_or(OAuthError::bad("expired_or_invalid_request",400))?;
        let request=self.validate_local_request(&doc,now)?;
        if !confirm_local_owner(&request){
            return Err(OAuthError::bad("local_owner_consent_required",403));
        }
        self.files.approve(&doc)
    }
    fn validate_local_request(
        &self,doc:&store::ApprovalRequest,now:i64
    )->Result<LocalApprovalRequest>{
        let callback=callback_family(&doc.redirect,false);
        if !token_shape(&doc.id)||!token_shape(&doc.binding_hash)
            || doc.expires<=now || doc.expires>expiry_ms(now,APPROVAL_TTL_MS)?
            || doc.scope!=SCOPE||doc.resource!=self.policy.resource
            || doc.audience!=self.policy.audience_str()
            || !doc.capability.validate()
            || (self.policy.audience!=Audience::Workstation && !doc.capability.is_legacy())
            || callback.is_none_or(|kind|!kind.matches_id(&doc.client_id))
        {
            return Err(OAuthError::bad("expired_or_invalid_request",400));
        }
        Ok(LocalApprovalRequest{
            id:doc.id.clone(),client_id:doc.client_id.clone(),
            redirect_uri:doc.redirect.clone(),resource:doc.resource.clone(),
            scope:doc.scope.clone(),expires_epoch_ms:doc.expires,
            audience:self.policy.audience,capability:doc.capability.clone(),
        })
    }
}
