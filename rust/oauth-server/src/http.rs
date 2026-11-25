//! Deterministic OAuth HTTP protocol adapter, intentionally without a listener.
//! The orchestrator owns TLS/Host validation, bind and admission, port selection,
//! bounded MCP request bodies, and the actual mission routing. No generic
//! proxying or workstation routing is performed here.
use crate::{
    AuthorizedIdentity, AuthorizationFlow, OAuthError, OAuthServer, Result,
};
use crate::model::{params, request_json, now_ms};
use serde_json::{json, Value};

/// Borrowed, already-framed HTTP request. The caller must validate Host,
/// forwarded-authority trust, TLS termination, body length, and method framing
/// before invoking the library. Do not construct from an unbounded body.
pub struct HttpRequest<'a>{
    pub method:&'a str,
    /// A relative request target (path and optional query), not an absolute URI.
    pub target:&'a str,
    pub origin:Option<&'a str>,
    pub authorization:Option<&'a str>,
    pub content_type:Option<&'a str>,
    pub body:&'a [u8],
}
/// Never derive Debug for OAuth HTTP bodies: these can carry credentials.
pub struct HttpResponse{
    pub status:u16,
    pub headers:Vec<(String,String)>,
    pub body:Vec<u8>,
}
impl HttpResponse{
    pub fn json(status:u16,body:Value)->Self{
        let data=serde_json::to_vec(&body)
            .unwrap_or_else(|_|b"{\"error\":\"server_error\"}".to_vec());
        Self::plain(status,"application/json",data)
    }
    pub fn text(status:u16,value:String)->Self{
        Self::plain(status,"text/plain; charset=utf-8",value.into_bytes())
    }
    fn plain(status:u16,content_type:&str,body:Vec<u8>)->Self{
        Self{status,headers:vec![
            ("content-type".into(),content_type.into()),
            ("cache-control".into(),"no-store".into()),
            ("x-content-type-options".into(),"nosniff".into()),
            ("referrer-policy".into(),"no-referrer".into()),
        ],body}
    }
    fn redirect(location:String)->Self{
        let mut result=Self::text(302,String::new());
        result.headers.push(("location".into(),location));
        result
    }
    fn unauthorized(metadata:&str)->Self{
        let mut reply=Self::json(401,json!({"error":"invalid_token"}));
        reply.headers.push(("www-authenticate".into(),
            format!("Bearer resource_metadata=\"{metadata}\", scope=\"mcp\"")));
        reply
    }
}
pub enum HttpAction {
    Reply(HttpResponse),
    /// Authenticated client identity to pass to the *mission* MCP router only.
    /// This never forwards an HTTP payload to an arbitrary upstream URL.
    McpAuthorized(AuthorizedIdentity),
}
impl OAuthServer {
    /// Public-only routes. No enrollment, local approval, local stop,
    /// management, process execution or proxy endpoint exists here.
    ///
    /// Invariant for the integrating host: if McpAuthorized is returned,
    /// immediately before processing an MCP request call authorize_mcp again,
    /// after completely reading its bounded body and checking the current
    /// audience and the target service. Never turn this decision into a
    /// persistent session, capability, or implicit workstation permission.
    pub fn handle_http(&mut self,request:HttpRequest<'_>)->HttpAction{
        match self.handle_checked(request){
            Ok(answer)=>answer,
            Err(error)=>HttpAction::Reply(failure(error)),
        }
    }
    fn handle_checked(&mut self,request:HttpRequest<'_>)->Result<HttpAction>{
        let now=now_ms()?;
        self.ensure_healthy()?;
        if request.target.len()>16_384 || !request.target.starts_with('/')
            || request.target.contains('#') || request.target.contains('\\')
        {return Err(OAuthError::bad("invalid_request",400));}
        if request.origin.is_some_and(|origin|origin!=self.policy.base.as_str()){
            return Err(OAuthError::bad("origin_refused",403));
        }
        let (path,query)=match request.target.split_once('?'){
            Some((p,q))=>(p,q),None=>(request.target,""),
        };
        self.prune(now)?;
        let exchange=request.method=="POST"
            && matches!(path,"/oauth/token"|"/oauth/revoke");
        if !exchange{
            let private=self.authorize_mcp_at(request.authorization,now).is_ok();
            self.count_request(private,now)?;
        }
        match (request.method,path){
            ("GET","/.well-known/oauth-authorization-server" |
                "/.well-known/openid-configuration")=>
            {
                Ok(HttpAction::Reply(HttpResponse::json(200,
                    self.policy.authorization_server_metadata())))
            }
            ("GET","/.well-known/oauth-protected-resource" |
                "/.well-known/oauth-protected-resource/mcp")=>
            {
                Ok(HttpAction::Reply(HttpResponse::json(200,
                    self.policy.protected_resource_metadata())))
            }
            ("GET","/health")=>
                Ok(HttpAction::Reply(HttpResponse::json(200,
                    json!({"ok":true,"name":"agent-bridge-gemini-access"})))),
            ("POST","/oauth/register")=>{
                require_content_type(request.content_type,"application/json")?;
                let payload=request_json(request.body)?;
                let reply=self.register(payload,now)?;
                Ok(HttpAction::Reply(HttpResponse::json(201,reply)))
            }
            ("GET","/oauth/authorize")=>{
                let input=params(query,16_384)?;
                match self.authorize(&input,now)?{
                    AuthorizationFlow::PendingLocalApproval(id)=>{
                        let scope=if self.policy.audience_str()=="workstation"{
                            "missions et outils de poste de travail de cet ordinateur"
                        }else{
                            "outils MCP de mission autorises localement"
                        };
                        Ok(HttpAction::Reply(HttpResponse::text(200,format!(
                            "Agent Bridge : approbation locale requise.\n\nDemande : {id}\nAcces : {scope}.\n\nLe proprietaire doit approuver cette demande localement. Actualisez ensuite cette page. Aucun acces n'est accorde en attendant.\n"
                        ))))
                    }
                    AuthorizationFlow::RedirectToGoogle(url)=>
                        Ok(HttpAction::Reply(HttpResponse::redirect(url)))
                }
            }
            ("POST","/oauth/token")=>{
                require_content_type(request.content_type,
                    "application/x-www-form-urlencoded")?;
                let input=params(std::str::from_utf8(request.body)
                    .map_err(|_|OAuthError::bad("invalid_request",400))?,16_384)?;
                // A public flood cannot exhaust the authenticated refresh
                // and revocation budget (1000/min vs 240/min).
                let authenticated=self.authenticate_client(request.authorization,&input).is_ok();
                self.count_request(authenticated,now)?;
                let response=self.exchange(&input,request.authorization,now)?;
                Ok(HttpAction::Reply(HttpResponse::json(200,response)))
            }
            ("POST","/oauth/revoke")=>{
                require_content_type(request.content_type,
                    "application/x-www-form-urlencoded")?;
                let input=params(std::str::from_utf8(request.body)
                    .map_err(|_|OAuthError::bad("invalid_request",400))?,16_384)?;
                // A public flood cannot exhaust the authenticated refresh
                // and revocation budget (1000/min vs 240/min).
                let authenticated=self.authenticate_client(request.authorization,&input).is_ok();
                self.count_request(authenticated,now)?;
                let response=self.revoke(&input,request.authorization,now)?;
                Ok(HttpAction::Reply(HttpResponse::json(200,response)))
            }
            ("GET"|"POST"|"DELETE","/mcp")=>{
                // This does not inspect or forward the MCP body: validation
                // before ACTUAL dispatch is a distinct mandatory call.
                match self.authorize_mcp_at(request.authorization,now){
                    Ok(identity)=>Ok(HttpAction::McpAuthorized(identity)),
                    Err(OAuthError::Bad{code:"invalid_token",..})=>{
                        Ok(HttpAction::Reply(HttpResponse::unauthorized(&format!(
                            "{}/.well-known/oauth-protected-resource",self.policy.base
                        ))))
                    },
                    Err(error)=>Err(error),
                }
            }
            _=>Ok(HttpAction::Reply(HttpResponse::json(404,json!({"error":"not_found"})))),
        }
    }
}
fn require_content_type(actual:Option<&str>,expected:&str)->Result<()>{
    let header=actual.unwrap_or("");
    let mut pieces=header.split(';');
    if !pieces.next().unwrap_or("").trim().eq_ignore_ascii_case(expected){
        return Err(OAuthError::bad("unsupported_content_type",415));
    }
    for parameter in pieces{
        let Some((key,value))=parameter.trim().split_once('=')else{
            return Err(OAuthError::bad("unsupported_content_type",415))
        };
        if !key.trim().eq_ignore_ascii_case("charset")
            || !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        {return Err(OAuthError::bad("unsupported_content_type",415));}
    }
    Ok(())
}
fn failure(error:OAuthError)->HttpResponse{
    // Do not leak filesystem paths, confidential request contents, hashes,
    // private grants or errors from the local host through the public API.
    match error {
        OAuthError::Bad{code,status}=>HttpResponse::json(status,json!({"error":code})),
        OAuthError::Busy=>HttpResponse::json(503,json!({"error":"connector_busy"})),
        _=>HttpResponse::json(503,json!({"error":"oauth_state_uncertain"})),
    }
}
