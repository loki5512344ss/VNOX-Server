mod audit;
mod crud;
mod invites;
mod list;
mod members;
mod members_list;
mod roles;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    domain::permissions::Permissions,
    net::{io, state::State},
    proto::{ErrorPayload, PacketId, SessionCrypto, to_payload},
};

async fn send_err(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    seq: &mut u32,
    code: crate::proto::ErrorCode,
    msg: &str,
    crypto: &SessionCrypto,
) -> Result<()> {
    io::send_encrypted(
        stream,
        PacketId::Error,
        seq,
        &to_payload(&ErrorPayload {
            code: code as u32,
            message: msg.into(),
        }),
        crypto,
    )
    .await
}

async fn require_perm(
    state: &State,
    guild_id: &str,
    user_id: &str,
    required: Permissions,
) -> Result<bool> {
    if let Some(g) = state.storage.get_guild(guild_id).await?
        && g.owner_id == user_id
    {
        return Ok(true);
    }
    if !state
        .storage
        .list_user_guilds(user_id)
        .await?
        .iter()
        .any(|g| g.id == guild_id)
    {
        return Ok(false);
    }
    let perms = state.storage.get_user_role_perms(guild_id, user_id).await?;
    Ok(Permissions::from_role_perms(&perms).has(required))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub use audit::handle_audit_log_fetch;
pub use crud::{handle_guild_create, handle_guild_delete};
pub use invites::{handle_invite_accept, handle_invite_create, handle_invite_delete};
pub use list::handle_guild_list;
pub use members::{handle_guild_member_join, handle_guild_member_kick, handle_guild_member_leave};
pub use members_list::{
    handle_member_list_fetch, handle_role_assign, handle_role_list_fetch, handle_role_unassign,
};
pub use roles::{handle_role_create, handle_role_delete};
