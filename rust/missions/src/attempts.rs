//! #123: durable, locally approved maintenance attempts on the existing v7
//! execution/operation ledger. No scheduler, process, new task or schema.
//!
//! The only supported mandate is a read-only verification of the approved
//! worktree's Git HEAD. The runtime supplies the physically qualified scope
//! and the fixed verifier; a remote caller cannot choose either.
use crate::{store::*, subtask::read_subtask};
use agent_bridge_leases::{bind_operation_id, Clock, LeaseCoordinator, LeaseError,
    ResourceLeaseGrant, SystemClock, UtcTimestamp};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

const PREPARE: &str = "Mission.Attempt.Prepare";
const EVENT: &str = "mission.attempt";
pub const LEASE_TTL: Duration = Duration::from_secs(30);
pub const HEARTBEAT_MIN: Duration = Duration::from_secs(5);
const CLAIM_MAX: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMandate {
    pub mandate: MandateKind,
    pub mission_id: String,
    pub subtask_id: String,
    // The same qualified binding digest used by the Task Room runtime.
    pub worktree_sha256: String,
    pub base_commit: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateKind { VerifyLocalGitHeadV1 }

fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_oid(value: &str) -> bool { hex(value, 40) || hex(value, 64) }

impl LocalMandate {
    pub fn from_qualified_workspace(mission_id: String, subtask_id: String,
        qualified_binding: &str, base_commit: String) -> Result<Self>
    {
        if qualified_binding.is_empty() { return Err(denied("Missing physical worktree binding.")); }
        let result = Self { mandate:MandateKind::VerifyLocalGitHeadV1, mission_id, subtask_id, base_commit,
            worktree_sha256: sha256_hex(format!("agent-bridge.task-room.workspace.v1\0{qualified_binding}")) };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        require_id("mis", &self.mission_id)?;
        require_id("sub", &self.subtask_id)?;
        if !hex(&self.worktree_sha256,64) || !valid_oid(&self.base_commit) {
            return Err(invalid("Invalid worktree or base digest."));
        }
        Ok(())
    }
    fn resource(&self) -> String { format!("git:worktree-sha256:{}", self.worktree_sha256) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared, Claimed, BlockedQuota, BlockedApproval, Running,
    Unknown, AwaitingReview, ReviewedPass, ReviewedFailed,
}

impl State {
    fn db(self) -> &'static str {
        match self {
            Self::Prepared=>"ab_attempt_prepared", Self::Claimed=>"ab_attempt_claimed",
            Self::BlockedQuota=>"ab_attempt_blocked_quota", Self::BlockedApproval=>"ab_attempt_blocked_approval",
            Self::Running=>"ab_attempt_running", Self::Unknown=>"ab_attempt_unknown",
            Self::AwaitingReview=>"ab_attempt_awaiting_review", Self::ReviewedPass=>"ab_attempt_reviewed_pass",
            Self::ReviewedFailed=>"ab_attempt_reviewed_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason { Quota, Approval, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision { Pass, Failed }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub observed_base: String,
    pub verified: bool,
    pub receipt_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Review {
    pub reviewer_context_id: String,
    pub decision: ReviewDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt_id: String,
    pub plan: LocalMandate,
    pub revision: i64,
    pub state: State,
    pub claimant_context_id: Option<String>,
    pub subtask_revision: Option<i64>,
    pub heartbeat_at: Option<UtcTimestamp>,
    pub evidence: Option<Evidence>,
    pub review: Option<Review>,
}

// Grant and bound operation identity remain in the ledger, never an MCP
// reply, local UI DTO, handoff, or client-provided field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    attempt: Attempt,
    root_operation_id: String,
    grant: Option<ResourceLeaseGrant>,
    claim_count: i64,
    claimed_at: Option<UtcTimestamp>,
    record_id: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub attempt: Attempt,
    pub lease_current: bool,
    // A lease is coordination authority, not proof the provider is alive.
    pub reconciliation_required: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Mutation {
    pub attempt: Attempt,
    pub replayed: bool,
}

pub struct Coordinator<C = SystemClock> { clock: C }
impl Default for Coordinator<SystemClock> {
    fn default() -> Self { Self::with_clock(SystemClock) }
}
fn lease_error(error: LeaseError) -> BridgeError {
    let code = match error.code() {
        "RESOURCE_BUSY" => "RESOURCE_BUSY",
        "STALE_OBSERVATION" => "STALE_FENCE",
        _ => "LEASE_REFUSED",
    };
    BridgeError::new(code, "Attempt resource lease refused; observe before another action.")
}
fn conflict() -> BridgeError { BridgeError::new("CONFLICT_REVISION","Attempt revision changed.") }
fn transition() -> BridgeError { BridgeError::new("ATTEMPT_TRANSITION_REFUSED","Attempt cannot perform this transition.") }
fn corrupt() -> BridgeError { BridgeError::new("ATTEMPT_LEDGER_INVALID","Attempt receipt is inconsistent.") }
fn uncertain() -> BridgeError { BridgeError::new("ATTEMPT_RECONCILIATION_REQUIRED","An effect may have occurred; never relaunch it.") }

fn public_actor(conn: &Connection, hash: &str) -> Result<String> {
    let id: String = conn.query_row("SELECT context_id FROM agent_contexts WHERE handle_hash=?1",
        [hash], |row| row.get(0))?;
    require_id("ctx", &id)?;
    Ok(id)
}

fn require_active(conn: &Connection, mission: &str) -> Result<MissionDto> {
    let current = fetch_mission(conn, mission)?;
    if current.status != "active" { return Err(transition()); }
    Ok(current)
}
fn task_revision(conn: &Connection, plan: &LocalMandate, actor: &str) -> Result<i64> {
    let task = read_subtask(conn,&plan.mission_id,&plan.subtask_id)?
        .ok_or_else(|| denied("Approved subtask is missing."))?;
    if task.status != "in_progress" || task.assignee_context_id.as_deref()!=Some(actor) {
        return Err(denied("Current in-progress assignment to this context is required."));
    }
    Ok(task.revision)
}

/// Preserve Task Room project isolation when the mission originated from a
/// locally imported room. An external import or a mission without a room
/// does not acquire an implicit Task Room capability.
fn check_room_binding(conn: &Connection, plan: &LocalMandate) -> Result<()> {
    let local: i64 = conn.query_row(
        "SELECT count(*) FROM imports WHERE target_mission_id=?1 AND source_provider='agent-bridge'",
        [&plan.mission_id],|r|r.get(0))?;
    if local == 0 { return Ok(()); }
    crate::task_room::verify_schema(conn)?;
    let matched: i64 = conn.query_row(
        "SELECT count(*) FROM imports i JOIN task_room_context_access a ON a.context_id=i.source_context_id
         JOIN task_room_tasks t ON t.task_id=i.source_task_id AND t.context_id=a.context_id
         WHERE i.target_mission_id=?1 AND i.source_provider='agent-bridge' AND a.workspace_binding=?2",
        params![plan.mission_id,plan.worktree_sha256],|r|r.get(0))?;
    if matched != local { return Err(denied("Imported Task Room belongs to another worktree.")); }
    Ok(())
}

fn load(conn: &Connection, mission: &str, id: &str) -> Result<Stored> {
    require_id("mis",mission)?;
    require_id("att",id)?;
    let row: Option<(String,String,i64,String,String,String,Option<String>,Option<String>)> = conn.query_row(
        "SELECT root.result_json, current.result_json, e.revision, e.state, e.operation_id,
                e.checkpoint_ref, e.command_digest, e.owner_instance
         FROM executions e JOIN operations root ON root.operation_id=e.operation_id
         JOIN operations current ON current.operation_id=e.checkpoint_ref AND current.mission_id=root.mission_id
         WHERE e.execution_id=?1 AND root.mission_id=?2 AND root.tool_name=?3",
        params![id,mission,PREPARE],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))
    ).optional()?;
    let (root,current,revision,state,operation,record,digest,owner) = row
        .ok_or_else(||BridgeError::new("NOT_FOUND","Attempt not found."))?;
    let initial: Stored = serde_json::from_str(&root).map_err(|_|corrupt())?;
    let current: Stored = serde_json::from_str(&current).map_err(|_|corrupt())?;
    let a = &current.attempt;
    a.plan.validate()?;
    if a.plan.mission_id!=mission || a.attempt_id!=id || a.revision!=revision
        || a.state.db()!=state || current.root_operation_id!=operation
        || current.record_id!=record || initial.attempt.plan!=a.plan
        || initial.attempt.attempt_id!=a.attempt_id || initial.root_operation_id!=operation
        || digest.as_deref()!=Some(digest_json(&a.plan)?.as_str())
        || owner!=a.claimant_context_id {
        return Err(corrupt());
    }
    if let Some(grant)=&current.grant {
        let bound=bind_operation_id(mission,&operation).map_err(lease_error)?;
        if grant.operation_id!=bound || grant.keys!=[a.plan.resource()]
            || grant.fences.len()!=1 || grant.fences.values().any(|f|*f<=0) {
            return Err(corrupt());
        }
    }
    if matches!(a.state, State::Claimed|State::Running) != current.grant.is_some() {
        return Err(corrupt());
    }
    Ok(current)
}

fn check_plan(stored: &Stored, plan: &LocalMandate) -> Result<()> {
    if &stored.attempt.plan != plan { return Err(denied("Attempt differs from approved mandate.")); }
    Ok(())
}
fn replay_ack(tx: &Transaction<'_>, key: &str, digest: &str, plan: &LocalMandate,
    id: Option<&str>) -> Result<Option<Mutation>>
{
    let prior: Option<Stored> = replay(tx,key,digest)?;
    if let Some(prior)=prior {
        check_plan(&prior,plan)?;
        if id.is_some_and(|id|id!=prior.attempt.attempt_id) { return Err(corrupt()); }
        return Ok(Some(Mutation { attempt:prior.attempt, replayed:true }));
    }
    Ok(None)
}
// Never persist caller-controlled idempotency text or let it collide with
// an internal completion receipt. Scope the digest to this protocol.
fn request_key(key:&str)->Result<String>{
    require_key(key)?;
    Ok(format!("attempt-request-v1:{}",sha256_hex(key.as_bytes())))
}

fn request_digest(action: &str, hash: &str, plan: &LocalMandate, id: Option<&str>,
    revision: i64, extra: serde_json::Value) -> Result<String>
{
    if !(1..=9_007_199_254_740_991).contains(&revision) { return Err(invalid("Observed revision required.")); }
    digest_json(&json!({"version":1,"action":action,"actor":hash,"plan":plan,
        "attempt_id":id,"if_revision":revision,"extra":extra}))
}

fn record(tx: &Transaction<'_>, stored: &mut Stored, key: &str, digest: &str,
    method: &str, now: UtcTimestamp, bump_mission: bool) -> Result<Mutation>
{
    let before = stored.attempt.revision;
    stored.attempt.revision = before.checked_add(1).ok_or_else(conflict)?;
    stored.record_id=new_id("op");
    if bump_mission {
        let mission=fetch_mission(tx,&stored.attempt.plan.mission_id)?;
        touch(tx,&mission,mission.revision)?;
    }
    let a=&stored.attempt;
    insert_operation(tx,&stored.record_id,&a.plan.mission_id,key,digest,stored,method)?;
    let heartbeat=a.heartbeat_at.map(|v|v.to_iso8601_o());
    let updated=tx.execute(
        "UPDATE executions SET state=?1,revision=?2,owner_instance=?3,heartbeat_utc=?4,
                updated_utc=?5,checkpoint_ref=?6
         WHERE execution_id=?7 AND operation_id=?8 AND revision=?9",
        params![a.state.db(),a.revision,a.claimant_context_id,heartbeat,now.to_iso8601_o(),
            stored.record_id,a.attempt_id,stored.root_operation_id,before])?;
    if updated!=1 { return Err(conflict()); }
    append_event(tx,&a.plan.mission_id,Some(&stored.record_id),EVENT,
        &json!({"attempt_id":a.attempt_id,"state":a.state}).to_string())?;
    Ok(Mutation{attempt:a.clone(),replayed:false})
}

impl<C: Clock+Clone> Coordinator<C> {
    pub fn with_clock(clock: C) -> Self { Self{clock} }
    fn leases(&self) -> LeaseCoordinator<C> { LeaseCoordinator::with_clock(self.clock.clone()) }
    fn current(&self,conn:&Connection,stored:&Stored)->Result<bool>{
        let Some(grant)=&stored.grant else{return Ok(false);};
        let now=self.clock.utc_now();
        let claimed=stored.claimed_at.ok_or_else(corrupt)?;
        let heartbeat=stored.attempt.heartbeat_at.ok_or_else(corrupt)?;
        if now<heartbeat || heartbeat<claimed || now>=claimed.checked_add(CLAIM_MAX).map_err(lease_error)? {
            return Ok(false);
        }
        self.leases().is_current(conn,grant).map_err(lease_error)
    }
    fn release(&self,tx:&Transaction<'_>,stored:&mut Stored)->Result<()>{
        if let Some(grant)=stored.grant.take() {
            self.leases().release_in_transaction(tx,&grant).map_err(lease_error)?;
        }
        stored.attempt.heartbeat_at=None;
        stored.claimed_at=None;
        Ok(())
    }
    fn require_claimant(&self,tx:&Transaction<'_>,stored:&Stored,actor:&str)->Result<()>{
        if stored.attempt.claimant_context_id.as_deref()!=Some(actor) {
            return Err(denied("Only the current claimed context can act."));
        }
        require_active(tx,&stored.attempt.plan.mission_id)?;
        check_room_binding(tx,&stored.attempt.plan)?;
        if Some(task_revision(tx,&stored.attempt.plan,actor)?)!=stored.attempt.subtask_revision {
            return Err(BridgeError::new("ASSIGNMENT_CHANGED","Observe and reconcile the subtask revision."));
        }
        if !self.current(tx,stored)? { return Err(BridgeError::new("STALE_FENCE","Attempt lease is not current.")); }
        Ok(())
    }

    /// Trusted operator-selected plan plus explicit mission-owner approval.
    /// No execution or lease is acquired by this operation.
    pub fn prepare(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,
        if_mission_revision:i64,key:&str)->Result<Mutation>
    {
        plan.validate()?; let key=request_key(key)?;
        write(conn,|tx|{
            let hash=require_context(tx,handle)?;
            membership(tx,&plan.mission_id,&hash,true)?;
            let digest=request_digest(PREPARE,&hash,plan,None,if_mission_revision,json!(null))?;
            if let Some(ack)=replay_ack(tx,&key,&digest,plan,None)? { return Ok(ack); }
            let mission=require_active(tx,&plan.mission_id)?;
            if mission.revision!=if_mission_revision { return Err(conflict()); }
            let task=read_subtask(tx,&plan.mission_id,&plan.subtask_id)?
                .ok_or_else(||denied("Approved subtask is missing."))?;
            if task.status=="completed" { return Err(transition()); }
            check_room_binding(tx,plan)?;
            // One immutable attempt per existing subtask; new keys cannot
            // bypass the original effect intent or its review.
            if find_attempt(tx,&plan.mission_id,&plan.subtask_id)?.is_some(){
                return Err(BridgeError::new("ATTEMPT_EXISTS","Observe the existing attempt."));
            }
            let id=new_id("att");
            let op=new_id("op");
            let a=Attempt{attempt_id:id,plan:plan.clone(),revision:1,state:State::Prepared,
                claimant_context_id:None,subtask_revision:None,heartbeat_at:None,evidence:None,review:None};
            let stored=Stored{attempt:a.clone(),root_operation_id:op.clone(),grant:None,claim_count:0,claimed_at:None,record_id:op.clone()};
            let now=self.clock.utc_now().to_iso8601_o();
            touch(tx,&mission,if_mission_revision)?;
            insert_operation(tx,&op,&plan.mission_id,&key,&digest,&stored,PREPARE)?;
            tx.execute("INSERT INTO executions(execution_id,attempt,operation_id,state,created_utc,updated_utc,
                        revision,checkpoint_ref,command_digest) VALUES(?1,1,?2,?3,?4,?4,1,?2,?5)",
                params![a.attempt_id,op,a.state.db(),now,digest_json(plan)?])?;
            append_event(tx,&plan.mission_id,Some(&op),EVENT,
                &json!({"attempt_id":a.attempt_id,"state":a.state}).to_string())?;
            Ok(Mutation{attempt:a,replayed:false})
        })
    }

    /// An assigned worker claims before effects. A lost pre-effect claim can
    /// be reclaimed with fresh CAS/assignment; a running/unknown attempt cannot.
    pub fn claim(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str)->Result<Mutation>
    {
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Claim",json!(null),false,|tx,s,actor|{
            let state=s.attempt.state;
            if !matches!(state,State::Prepared|State::BlockedQuota|State::BlockedApproval|State::Claimed) {
                return Err(if matches!(state,State::Running|State::Unknown){uncertain()}else{transition()});
            }
            if state==State::Claimed && self.current(tx,s)? { return Err(BridgeError::new("RESOURCE_BUSY","Attempt is already claimed.")); }
            require_active(tx,&plan.mission_id)?;
            check_room_binding(tx,plan)?;
            let task_rev=task_revision(tx,plan,actor)?;
            // A different task's lease expiry cannot authorize another
            // effect while any earlier worktree intent is unresolved.
            let unresolved:bool=tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM executions e JOIN operations o ON o.operation_id=e.operation_id
                 WHERE o.tool_name=?1 AND e.execution_id<>?2
                   AND json_extract(o.result_json,'$.attempt.plan.worktree_sha256')=?3
                   AND e.state IN ('ab_attempt_running','ab_attempt_unknown'))",
                params![PREPARE,id,plan.worktree_sha256],|r|r.get(0))?;
            if unresolved {return Err(uncertain());}
            let owner=bind_operation_id(&plan.mission_id,&s.root_operation_id).map_err(lease_error)?;
            let grant=self.leases().acquire_in_transaction(tx,&[plan.resource()],&owner,LEASE_TTL).map_err(lease_error)?;
            s.claim_count=s.claim_count.checked_add(1).ok_or_else(conflict)?;
            s.grant=Some(grant);
            s.attempt.state=State::Claimed;
            s.attempt.claimant_context_id=Some(actor.into());
            s.attempt.subtask_revision=Some(task_rev);
            let now=self.clock.utc_now();
            s.claimed_at=Some(now);
            s.attempt.heartbeat_at=Some(now);
            Ok(())
        })
    }

    /// Only pre-effect claims are renewed. Cadence is enforced before any
    /// lease/ledger write; a throttled call consumes no idempotency key.
    pub fn heartbeat(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str)->Result<Mutation>
    {
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Heartbeat",json!(null),false,|tx,s,actor|{
            if s.attempt.state!=State::Claimed { return Err(transition()); }
            self.require_claimant(tx,s,actor)?;
            let now=self.clock.utc_now();
            let last=s.attempt.heartbeat_at.ok_or_else(corrupt)?;
            if now < last.checked_add(HEARTBEAT_MIN).map_err(lease_error)? {
                return Err(BridgeError::new("HEARTBEAT_THROTTLED","Heartbeat cadence is at least five seconds."));
            }
            if now.checked_add(LEASE_TTL).map_err(lease_error)?
                > s.claimed_at.ok_or_else(corrupt)?.checked_add(CLAIM_MAX).map_err(lease_error)? {
                return Err(BridgeError::new("ATTEMPT_CLAIM_LIMIT","Maximum continuous claim duration reached; let the lease expire."));
            }
            let renewed=self.leases().renew_in_transaction(tx,s.grant.as_ref().ok_or_else(corrupt)?,LEASE_TTL)
                .map_err(lease_error)?;
            s.grant=Some(renewed);
            s.attempt.heartbeat_at=Some(now);
            Ok(())
        })
    }

    /// Report a blocker before any effect. Quota and approval can be resumed
    /// explicitly; unknown stays quarantined. Never infer a blocker by scraping.
    pub fn block(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str,reason:BlockReason)->Result<Mutation>
    {
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Block",json!(reason),false,|tx,s,actor|{
            if s.attempt.state!=State::Claimed { return Err(transition()); }
            self.require_claimant(tx,s,actor)?;
            self.release(tx,s)?;
            s.attempt.state=match reason {BlockReason::Quota=>State::BlockedQuota,
                BlockReason::Approval=>State::BlockedApproval,BlockReason::Unknown=>State::Unknown};
            Ok(())
        })
    }

    /// Recover an interrupted running intent only as unknown. A live fence
    /// cannot be revoked by this operation. Unknown is not a retry state.
    pub fn recover_unknown(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str)->Result<Mutation>
    {
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Recover",json!(null),true,|tx,s,_|{
            if s.attempt.state!=State::Running || self.current(tx,s)? { return Err(transition()); }
            self.release(tx,s)?;
            s.attempt.state=State::Unknown;
            Ok(())
        })
    }

    // Only a freshly committed intent grants the in-process execution path.
    // No replay or public DTO is an execution capability.
    fn begin(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str)->Result<Mutation>
    {
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Begin",json!(null),false,|tx,s,actor|{
            if s.attempt.state!=State::Claimed {
                return Err(if matches!(s.attempt.state,State::Running|State::Unknown){uncertain()}else{transition()});
            }
            self.require_claimant(tx,s,actor)?;
            s.attempt.state=State::Running;
            Ok(())
        })
    }

    /// The closure is a trusted, bounded, read-only local HEAD verifier, never
    /// a command string or remote callback. Intent is committed FIRST. The
    /// second transaction fences the actual read and records its receipt.
    /// Panic, crash, failed read or uncertain commit never reissues the effect.
    pub fn verify_base(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str,read_head:impl FnOnce()->Result<String>)->Result<Mutation>
    {
        let intent=self.begin(conn,handle,plan,id,revision,key)?;
        if intent.replayed {return Ok(intent);}
        let finish_key=format!("attempt-receipt:{id}:{}",intent.attempt.revision);
        write(conn,|tx|{
            let hash=require_context(tx,handle)?;
            membership(tx,&plan.mission_id,&hash,false)?;
            let actor=public_actor(tx,&hash)?;
            let mut s=load(tx,&plan.mission_id,id)?;
            check_plan(&s,plan)?;
            if s.attempt.state!=State::Running || s.attempt.revision!=intent.attempt.revision {
                return Err(uncertain());
            }
            self.require_claimant(tx,&s,&actor)?;
            let oid=read_head().map_err(|_|uncertain())?;
            if !valid_oid(&oid) || !self.current(tx,&s)? {return Err(uncertain());}
            // The actual evidence is closed and bounded, not a claimed success
            // supplied by a member or arbitrary command output.
            let evidence=Evidence{verified:oid==plan.base_commit,observed_base:oid,receipt_id:new_id("rcpt")};
            let digest=request_digest("Mission.Attempt.Receipt",&hash,plan,Some(id),
                s.attempt.revision,json!(evidence))?;
            self.release(tx,&mut s)?;
            s.attempt.state=State::AwaitingReview;
            s.attempt.evidence=Some(evidence);
            record(tx,&mut s,&finish_key,&digest,"Mission.Attempt.Receipt",self.clock.utc_now(),true)
        })
    }

    /// The current mission owner, distinct from the executing context, must
    /// review the exact receipt. A mismatch cannot be approved as successful.
    pub fn review(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str,receipt_id:&str,decision:ReviewDecision)->Result<Mutation>
    {
        require_id("rcpt",receipt_id)?;
        self.change(conn,handle,plan,id,revision,key,"Mission.Attempt.Review",
            json!({"receipt_id":receipt_id,"decision":decision}),true,|_,s,actor|{
            if s.attempt.state!=State::AwaitingReview || s.attempt.claimant_context_id.as_deref()==Some(actor) {
                return Err(transition());
            }
            let evidence=s.attempt.evidence.as_ref().ok_or_else(corrupt)?;
            if evidence.receipt_id!=receipt_id || decision==ReviewDecision::Pass && !evidence.verified {
                return Err(denied("Exact verified receipt is required for a passing review."));
            }
            s.attempt.review=Some(Review{reviewer_context_id:actor.into(),decision});
            s.attempt.state=if decision==ReviewDecision::Pass {State::ReviewedPass}else{State::ReviewedFailed};
            Ok(())
        })
    }

    fn change(&self,conn:&mut Connection,handle:&str,plan:&LocalMandate,id:&str,
        revision:i64,key:&str,method:&str,extra:serde_json::Value,owner_only:bool,
        change:impl FnOnce(&Transaction<'_>,&mut Stored,&str)->Result<()>)->Result<Mutation>
    {
        plan.validate()?; let key=request_key(key)?; require_id("att",id)?;
        write(conn,|tx|{
            let hash=require_context(tx,handle)?;
            membership(tx,&plan.mission_id,&hash,owner_only)?;
            let actor=public_actor(tx,&hash)?;
            let digest=request_digest(method,&hash,plan,Some(id),revision,extra)?;
            if let Some(ack)=replay_ack(tx,&key,&digest,plan,Some(id))? { return Ok(ack); }
            let mut stored=load(tx,&plan.mission_id,id)?;
            check_plan(&stored,plan)?;
            if stored.attempt.revision!=revision { return Err(conflict()); }
            if fetch_mission(tx,&plan.mission_id)?.status=="completed" {return Err(transition());}
            change(tx,&mut stored,&actor)?;
            record(tx,&mut stored,&key,&digest,method,self.clock.utc_now(),method!="Mission.Attempt.Heartbeat")
        })
    }

    fn observation(&self,conn:&Connection,s:Stored)->Result<Observation>{
        let current=self.current(conn,&s)?;
        Ok(Observation{lease_current:current,
            reconciliation_required:matches!(s.attempt.state,State::Unknown|State::Running),
            attempt:s.attempt})
    }

    /// Member read path. No new lease, heartbeat or effect is inferred.
    pub fn get(&self,conn:&Connection,handle:&str,plan:&LocalMandate)->Result<Option<Observation>>{
        plan.validate()?; verify_schema(conn)?;
        let tx=conn.unchecked_transaction()?;
        let hash=require_context(&tx,handle)?;
        membership(&tx,&plan.mission_id,&hash,false)?;
        let answer=find_attempt(&tx,&plan.mission_id,&plan.subtask_id)?
            .map(|id|{let s=load(&tx,&plan.mission_id,&id)?;check_plan(&s,plan)?;self.observation(&tx,s)})
            .transpose()?;
        tx.commit()?;
        Ok(answer)
    }

    /// Existing authenticated local operator projection; no raw grant or
    /// actor capability. The caller chooses the existing authorized project.
    pub fn operator_snapshot(&self,conn:&Connection,limit:i64)->Result<Vec<Observation>>{
        verify_schema(conn)?;
        if !(1..=100).contains(&limit){return Err(invalid("Attempt inspection limit must be 1-100."));}
        let tx=conn.unchecked_transaction()?;
        let ids={
            let mut stmt=tx.prepare("SELECT e.execution_id,o.mission_id FROM executions e
                JOIN operations o ON o.operation_id=e.operation_id WHERE o.tool_name=?1
                ORDER BY e.updated_utc DESC,e.execution_id LIMIT ?2")?;
            let rows=stmt.query_map(params![PREPARE,limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut out=Vec::with_capacity(ids.len());
        for (id,mission) in ids {out.push(self.observation(&tx,load(&tx,&mission,&id)?)?);}
        tx.commit()?;
        Ok(out)
    }
}

fn find_attempt(conn:&Connection,mission:&str,subtask:&str)->Result<Option<String>>{
    let mut stmt=conn.prepare("SELECT e.execution_id FROM executions e JOIN operations o ON o.operation_id=e.operation_id
        WHERE o.mission_id=?1 AND o.tool_name=?2 AND json_extract(o.result_json,'$.attempt.plan.subtask_id')=?3 LIMIT 2")?;
    let mut rows=stmt.query(params![mission,PREPARE,subtask])?;
    let id=rows.next()?.map(|r|r.get(0)).transpose()?;
    if rows.next()?.is_some(){return Err(corrupt());}
    Ok(id)
}

/// Preserve existing subtask completion for all legacy tasks. Once a local
/// attempt is explicitly approved, completion requires its independent pass.
pub(crate) fn require_review_before_completion(conn:&Connection,mission:&str,subtask:&str)->Result<()>{
    if let Some(id)=find_attempt(conn,mission,subtask)? {
        if load(conn,mission,&id)?.attempt.state!=State::ReviewedPass {
            return Err(BridgeError::new("ATTEMPT_REVIEW_REQUIRED","The approved attempt needs a passing independent review."));
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mission, subtask};
    use agent_bridge_core::CoreDatabase;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::cell::Cell;

    #[derive(Clone)]
    struct TestClock(Arc<Mutex<UtcTimestamp>>);
    impl TestClock {
        fn new()->Self {Self(Arc::new(Mutex::new(UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap())))}
        fn advance(&self,seconds:u64) {
            let mut time=self.0.lock().unwrap();
            *time=time.checked_add(Duration::from_secs(seconds)).unwrap();
        }
    }
    impl Clock for TestClock {
        fn utc_now(&self)->UtcTimestamp{*self.0.lock().unwrap()}
    }
    struct Fixture {
        root:PathBuf,
        db:Option<CoreDatabase>,
        owner:ContextCreated,
        worker:ContextCreated,
        first:LocalMandate,
        second:LocalMandate,
        clock:TestClock,
    }
    impl Fixture {
        fn new()->Self{
            let base=std::fs::canonicalize(std::env::temp_dir()).unwrap();
            #[cfg(windows)]
            let base=base.to_str().and_then(|s|s.strip_prefix(r"\\?\"))
                .map(PathBuf::from).unwrap_or(base);
            let root=base.join(format!("ab-attempts-{}",new_guid_n()));
            std::fs::create_dir(&root).unwrap();
            let mut db=CoreDatabase::initialize_new(root.join("core.sqlite")).unwrap();
            crate::task_room::init_schema(db.connection_mut()).unwrap();
            let conn=db.connection_mut();
            let owner=create_context(conn).unwrap();
            let worker=create_context(conn).unwrap();
            let result=crate::dispatch_tool(conn,"agent_bridge_mission_create",&json!({
                "actor_context_handle":owner.context_handle,"goal":"Local approved maintenance",
                "idempotency_key":"fixture-mission"})).unwrap();
            let id=result["mission_id"].as_str().unwrap().to_owned();
            let invited=mission::grant_mission(conn,&owner.context_handle,mission::HandoffRequest{
                mission_id:id.clone(),if_revision:1,target_context_id:Some(worker.context_id.clone()),
                target_context_handle:None}).unwrap();
            mission::attach_mission(conn,&worker.context_handle,&id,invited.revision).unwrap();
            let mut make_task=|actor:&ContextCreated,key:&str|{
                let task=subtask::create_subtask(conn,&owner.context_handle,subtask::CreateSubtaskRequest{
                    mission_id:id.clone(),goal:"Verify approved local HEAD".into(),
                    idempotency_key:format!("task-{key}"),assignee_context_id:Some(actor.context_id.clone())
                }).unwrap().subtask;
                subtask::update_subtask(conn,&actor.context_handle,subtask::UpdateSubtaskRequest{
                    mission_id:id.clone(),subtask_id:task.subtask_id.clone(),if_revision:task.revision,
                    status:"in_progress".into(),idempotency_key:format!("start-{key}"),summary:None
                }).unwrap();
                LocalMandate::from_qualified_workspace(id.clone(),task.subtask_id,
                    "synthetic-qualified-worktree","a".repeat(40)).unwrap()
            };
            let first=make_task(&worker,"one");
            let second=make_task(&owner,"two");
            Self{root,db:Some(db),owner,worker,first,second,clock:TestClock::new()}
        }
        fn conn(&mut self)->&mut Connection{self.db.as_mut().unwrap().connection_mut()}
        fn reopen(&mut self){
            drop(self.db.take());
            self.db=Some(CoreDatabase::open_existing(self.root.join("core.sqlite")).unwrap());
        }
        fn prepared(&mut self)->(Attempt,Attempt){
            let c=Coordinator::with_clock(self.clock.clone());
            let owner=self.owner.context_handle.clone();
            let first=self.first.clone();let second=self.second.clone();
            let rev=mission::get_mission(self.conn(),&owner,&first.mission_id).unwrap().revision;
            let a=c.prepare(self.conn(),&owner,&first,rev,"prepare-one").unwrap().attempt;
            assert!(c.prepare(self.conn(),&owner,&first,rev,"prepare-one").unwrap().replayed);
            let rev=mission::get_mission(self.conn(),&owner,&first.mission_id).unwrap().revision;
            assert_eq!(c.prepare(self.conn(),&owner,&first,rev,"prepare-again").unwrap_err().code,"ATTEMPT_EXISTS");
            let b=c.prepare(self.conn(),&owner,&second,rev,"prepare-two").unwrap().attempt;
            (a,b)
        }
    }
    impl Drop for Fixture{
        fn drop(&mut self){drop(self.db.take());let _=std::fs::remove_dir_all(&self.root);}
    }

    #[test]
    fn attempts_two_contexts_cas_heartbeat_block_resume_and_independent_review(){
        let mut f=Fixture::new();
        let c=Coordinator::with_clock(f.clock.clone());
        let owner=f.owner.context_handle.clone();let worker=f.worker.context_handle.clone();
        let first=f.first.clone();let second=f.second.clone();
        let (a,b)=f.prepared();
        let id=&a.attempt_id;let other=&b.attempt_id;
        assert_eq!(c.claim(f.conn(),&owner,&first,id,1,"wrong-assignee").unwrap_err().code,"SECURITY_DENIED");
        let claimed=c.claim(f.conn(),&worker,&first,id,1,"claim-one").unwrap();
        assert_eq!(claimed.attempt.state,State::Claimed);
        assert!(c.claim(f.conn(),&worker,&first,id,1,"claim-one").unwrap().replayed);
        assert_eq!(c.claim(f.conn(),&owner,&second,other,1,"contender").unwrap_err().code,"RESOURCE_BUSY");
        let rev=claimed.attempt.revision;
        let writes=f.conn().total_changes();
        assert_eq!(c.heartbeat(f.conn(),&worker,&first,id,rev,"heartbeat").unwrap_err().code,"HEARTBEAT_THROTTLED");
        assert_eq!(writes,f.conn().total_changes());
        f.clock.advance(5);
        let mission_revision=fetch_mission(f.conn(),&first.mission_id).unwrap().revision;
        let beat=c.heartbeat(f.conn(),&worker,&first,id,rev,"heartbeat").unwrap();
        assert_eq!(fetch_mission(f.conn(),&first.mission_id).unwrap().revision,mission_revision);
        assert!(c.heartbeat(f.conn(),&worker,&first,id,rev,"heartbeat").unwrap().replayed);
        assert_eq!(c.heartbeat(f.conn(),&worker,&first,id,rev,"stale-heartbeat").unwrap_err().code,"CONFLICT_REVISION");
        let blocked=c.block(f.conn(),&worker,&first,id,beat.attempt.revision,"quota",BlockReason::Quota).unwrap();
        assert_eq!(blocked.attempt.state,State::BlockedQuota);
        let competing=c.claim(f.conn(),&owner,&second,other,1,"contender").unwrap();
        let paused=c.block(f.conn(),&owner,&second,other,competing.attempt.revision,"approval",BlockReason::Approval).unwrap();
        assert_eq!(paused.attempt.state,State::BlockedApproval);

        let resumed=c.claim(f.conn(),&worker,&first,id,blocked.attempt.revision,"resume-one").unwrap();
        let calls=Cell::new(0);
        let receipt=c.verify_base(f.conn(),&worker,&first,id,resumed.attempt.revision,"verify-once",||{
            calls.set(calls.get()+1);Ok(first.base_commit.clone())
        }).unwrap();
        assert_eq!(receipt.attempt.state,State::AwaitingReview);
        let replay=c.verify_base(f.conn(),&worker,&first,id,resumed.attempt.revision,"verify-once",||{
            calls.set(calls.get()+1);panic!("A replay must not execute.")
        }).unwrap();
        assert!(replay.replayed);
        assert_eq!(calls.get(),1);
        let current=c.get(f.conn(),&worker,&first).unwrap().unwrap();
        assert_eq!(current.attempt.state,State::AwaitingReview);
        assert!(!current.lease_current);
        let evidence=receipt.attempt.evidence.as_ref().unwrap();
        assert!(evidence.verified);
        f.reopen();
        assert_eq!(c.get(f.conn(),&worker,&first).unwrap().unwrap().attempt.evidence.as_ref(),Some(evidence));
        let task=read_subtask(f.conn(),&first.mission_id,&first.subtask_id).unwrap().unwrap();
        let complete=subtask::UpdateSubtaskRequest{
            mission_id:first.mission_id.clone(),subtask_id:first.subtask_id.clone(),if_revision:task.revision,
            status:"completed".into(),idempotency_key:"complete-one".into(),summary:Some("Reviewed evidence".into())};
        assert_eq!(subtask::update_subtask(f.conn(),&worker,complete.clone()).unwrap_err().code,"ATTEMPT_REVIEW_REQUIRED");
        assert_eq!(c.review(f.conn(),&worker,&first,id,receipt.attempt.revision,
            "self-review",&evidence.receipt_id,ReviewDecision::Pass).unwrap_err().code,"SECURITY_DENIED");
        let reviewed=c.review(f.conn(),&owner,&first,id,receipt.attempt.revision,
            "review-one",&evidence.receipt_id,ReviewDecision::Pass).unwrap();
        assert_eq!(reviewed.attempt.state,State::ReviewedPass);
        assert_eq!(subtask::update_subtask(f.conn(),&worker,complete).unwrap().subtask.status,"completed");
        let projected=serde_json::to_string(&c.operator_snapshot(f.conn(),20).unwrap()).unwrap();
        assert!(!projected.contains(&worker)&&!projected.contains(&owner));
        assert!(!projected.contains("\"grant\"")&&!projected.contains("\"fences\""));
        assert_eq!(calls.get(),1);
    }

    #[test]
    fn attempts_expired_fence_and_interrupted_receipt_never_duplicate_effect(){
        let mut f=Fixture::new();
        let c=Coordinator::with_clock(f.clock.clone());
        let owner=f.owner.context_handle.clone();let worker=f.worker.context_handle.clone();
        let first=f.first.clone();let second=f.second.clone();
        let (a,b)=f.prepared();
        let id=&a.attempt_id;let other=&b.attempt_id;
        let claimed=c.claim(f.conn(),&worker,&first,id,1,"claim-a").unwrap();
        let old=load(f.conn(),&first.mission_id,id).unwrap().grant.unwrap();
        f.clock.advance(31);
        let b_claim=c.claim(f.conn(),&owner,&second,other,1,"claim-b").unwrap();
        assert!(!c.leases().is_current(f.conn(),&old).unwrap());
        let calls=Cell::new(0);
        assert_eq!(c.verify_base(f.conn(),&worker,&first,id,claimed.attempt.revision,"stale-verify",||{
            calls.set(calls.get()+1);Ok(first.base_commit.clone())
        }).unwrap_err().code,"STALE_FENCE");
        assert_eq!(calls.get(),0);
        assert_eq!(c.heartbeat(f.conn(),&worker,&first,id,claimed.attempt.revision,"stale-fence").unwrap_err().code,"STALE_FENCE");
        let b_block=c.block(f.conn(),&owner,&second,other,b_claim.attempt.revision,"block-b",BlockReason::Approval).unwrap();
        let resumed=c.claim(f.conn(),&worker,&first,id,claimed.attempt.revision,"reclaim-a").unwrap();
        let new=load(f.conn(),&first.mission_id,id).unwrap().grant.unwrap();
        assert!(new.fences.values().next().unwrap()>old.fences.values().next().unwrap());
        c.leases().release(f.conn(),&old).unwrap();
        assert!(c.leases().is_current(f.conn(),&new).unwrap());

        // The real intent commit survives a panic inside the receipt
        // transaction. Dropping/reopening the file models interruption, not
        // physical power-loss or a qualified provider process crash.
        let crashed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            let _=c.verify_base(f.conn(),&worker,&first,id,resumed.attempt.revision,"crash-verify",||{
                calls.set(calls.get()+1);panic!("synthetic interruption after effect")
            });
        }));
        assert!(crashed.is_err());
        assert_eq!(calls.get(),1);
        f.reopen();
        let observed=c.get(f.conn(),&worker,&first).unwrap().unwrap();
        assert_eq!(observed.attempt.state,State::Running);
        assert!(observed.reconciliation_required);
        assert!(c.verify_base(f.conn(),&worker,&first,id,resumed.attempt.revision,"crash-verify",||{
            panic!("A committed intent is never issued again.")
        }).unwrap().replayed);
        f.clock.advance(31);
        let stale=c.get(f.conn(),&owner,&first).unwrap().unwrap();
        assert!(!stale.lease_current);
        assert_eq!(c.claim(f.conn(),&owner,&second,other,b_block.attempt.revision,"claim-after-crash").unwrap_err().code,
            "ATTEMPT_RECONCILIATION_REQUIRED");
        let unknown=c.recover_unknown(f.conn(),&owner,&first,id,stale.attempt.revision,"recover").unwrap();
        assert_eq!(unknown.attempt.state,State::Unknown);
        assert_eq!(c.claim(f.conn(),&worker,&first,id,unknown.attempt.revision,"never-reclaim").unwrap_err().code,
            "ATTEMPT_RECONCILIATION_REQUIRED");
        assert_eq!(c.claim(f.conn(),&owner,&second,other,b_block.attempt.revision,"still-quarantined").unwrap_err().code,
            "ATTEMPT_RECONCILIATION_REQUIRED");
        assert_eq!(calls.get(),1);
    }

    #[test]
    fn attempts_mismatched_base_never_passes_review(){
        let mut f=Fixture::new();
        let c=Coordinator::with_clock(f.clock.clone());
        let owner=f.owner.context_handle.clone();let worker=f.worker.context_handle.clone();
        let plan=f.first.clone();
        let (a,_)=f.prepared();
        let id=&a.attempt_id;
        let claimed=c.claim(f.conn(),&worker,&plan,id,1,"claim-mismatch").unwrap();
        let receipt=c.verify_base(f.conn(),&worker,&plan,id,claimed.attempt.revision,
            "verify-mismatch",||Ok("b".repeat(40))).unwrap();
        let evidence=receipt.attempt.evidence.as_ref().unwrap();
        assert!(!evidence.verified);
        assert_eq!(c.review(f.conn(),&owner,&plan,id,receipt.attempt.revision,
            "false-pass",&evidence.receipt_id,ReviewDecision::Pass).unwrap_err().code,"SECURITY_DENIED");
        let reviewed=c.review(f.conn(),&owner,&plan,id,receipt.attempt.revision,
            "failed-review",&evidence.receipt_id,ReviewDecision::Failed).unwrap();
        assert_eq!(reviewed.attempt.state,State::ReviewedFailed);
        assert!(require_review_before_completion(f.conn(),&plan.mission_id,&plan.subtask_id).is_err());
        assert!(c.claim(f.conn(),&worker,&plan,id,reviewed.attempt.revision,"retry-mismatch").is_err());
    }

    #[test]
    fn attempts_fixed_plan_and_imported_task_room_scope_are_authoritative(){
        let mut f=Fixture::new();
        let c=Coordinator::with_clock(f.clock.clone());
        let owner=f.owner.context_handle.clone();
        let plan=f.first.clone();
        let room=crate::task_room::dispatch_scoped(f.conn(),&json!({"action":"context_create",
            "context_label":"Other project"}),"other-qualified-worktree").unwrap();
        let handle=room["context_handle"].as_str().unwrap();
        let task=crate::task_room::dispatch_scoped(f.conn(),&json!({"action":"create",
            "context_handle":handle,"title":"Fixture","goal":"Review",
            "steps":[{"id":"check","title":"Check"}]}),"other-qualified-worktree").unwrap();
        let room_id=room["context_id"].as_str().unwrap();
        let task_id=task["task"]["task_id"].as_str().or_else(||task["task_id"].as_str()).unwrap();
        f.conn().execute("INSERT INTO imports(source_provider,source_context_id,source_task_id,source_digest,
            target_mission_id,imported_at,state) VALUES('agent-bridge',?1,?2,?3,?4,?5,'imported')",
            params![room_id,task_id,"a".repeat(64),plan.mission_id,now()]).unwrap();
        let rev=fetch_mission(f.conn(),&plan.mission_id).unwrap().revision;
        assert_eq!(c.prepare(f.conn(),&owner,&plan,rev,"cross-room").unwrap_err().code,"SECURITY_DENIED");
        assert!(c.operator_snapshot(f.conn(),20).unwrap().is_empty());
    }
}
