use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::{
    net::io,
    proto::{
        ChatMessagePayload, JoinChannelPayload, LeaveChannelPayload, PacketId, PingPayload,
        PongPayload, ReactionPayload, to_payload,
    },
};

use super::{Ctx, channel, content, direct_message, e2ee, friends, guild};

pub async fn dispatch<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &mut Ctx<'_, S>,
    session_id: &str,
    pid: PacketId,
    payload: &[u8],
    addr: std::net::SocketAddr,
) -> Result<()> {
    match pid {
        PacketId::Ping => {
            let ping = PingPayload::decode(payload)?;
            io::send_encrypted(
                ctx.stream,
                PacketId::Pong,
                ctx.seq,
                &to_payload(&PongPayload {
                    timestamp: ping.timestamp,
                }),
                ctx.crypto,
            )
            .await?;
        }
        PacketId::JoinChannel => {
            let m = JoinChannelPayload::decode(payload)?;
            channel::join(
                ctx.stream,
                ctx.seq,
                session_id,
                &m.channel_id,
                ctx.crypto,
                ctx.state,
                addr,
            )
            .await?;
        }
        PacketId::LeaveChannel => {
            let m = LeaveChannelPayload::decode(payload)?;
            channel::leave(
                ctx.stream,
                ctx.seq,
                session_id,
                &m.channel_id,
                ctx.crypto,
                ctx.state,
            )
            .await?;
        }
        PacketId::ChannelCreate => {
            channel::handle_channel_create(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::ChannelDelete => {
            channel::handle_channel_delete(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::ChannelEdit => {
            channel::handle_channel_edit(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::ChannelList => {
            channel::handle_channel_list(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::ChatMessage => {
            let m = ChatMessagePayload::decode(payload)?;
            content::chat::handle(session_id, m, ctx.state).await?;
        }
        PacketId::DmStart => {
            direct_message::handle_dm_start(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::DmMessage => {
            direct_message::handle_dm_message(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::DmHistory => {
            direct_message::handle_dm_history(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::DmReadAck => {
            direct_message::handle_dm_read_ack(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildCreate => {
            guild::handle_guild_create(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildDelete => {
            guild::handle_guild_delete(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildList => {
            guild::handle_guild_list(ctx.stream, ctx.seq, session_id, ctx.crypto, ctx.state)
                .await?;
        }
        PacketId::GuildMemberJoin => {
            guild::handle_guild_member_join(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildMemberLeave => {
            guild::handle_guild_member_leave(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildMemberKick => {
            guild::handle_guild_member_kick(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::RoleCreate => {
            guild::handle_role_create(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::RoleDelete => {
            guild::handle_role_delete(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::InviteCreate => {
            guild::handle_invite_create(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::InviteAccept => {
            guild::handle_invite_accept(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::InviteDelete => {
            guild::handle_invite_delete(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildAuditLogFetch => {
            guild::handle_audit_log_fetch(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildMemberListFetch => {
            guild::handle_member_list_fetch(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildRoleAssign => {
            guild::handle_role_assign(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildRoleUnassign => {
            guild::handle_role_unassign(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::GuildRoleListFetch => {
            guild::handle_role_list_fetch(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::PresenceUpdate => {
            content::presence::handle_presence_update(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::PresenceSync => {
            content::presence::handle_presence_sync(
                ctx.stream, ctx.seq, session_id, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::FriendRequest => {
            friends::handle_friend_request(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::FriendAccept => {
            friends::handle_friend_accept(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::FriendDecline => {
            friends::handle_friend_decline(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::FriendRemove => {
            friends::handle_friend_remove(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::FriendList => {
            friends::handle_friend_list(ctx.stream, ctx.seq, session_id, ctx.crypto, ctx.state)
                .await?;
        }
        PacketId::BlockUser => {
            friends::handle_block_user(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::UnblockUser => {
            friends::handle_unblock_user(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::BlockList => {
            friends::handle_block_list(ctx.stream, ctx.seq, session_id, ctx.crypto, ctx.state)
                .await?;
        }
        PacketId::MessageReactionAdd => {
            let m = ReactionPayload::decode(payload)?;
            content::reaction::handle_reaction_add(session_id, m, ctx.state).await?;
        }
        PacketId::MessageReactionRemove => {
            let m = ReactionPayload::decode(payload)?;
            content::reaction::handle_reaction_remove(session_id, m, ctx.state).await?;
        }
        PacketId::MessageEdit => {
            content::message_edit::handle_message_edit(session_id, payload, ctx.state).await?;
        }
        PacketId::MessageDelete => {
            content::message_edit::handle_message_delete(session_id, payload, ctx.state).await?;
        }
        PacketId::TypingStart => {
            content::handle_typing_start(session_id, payload, ctx.state).await?;
        }
        PacketId::ReadReceipt => {
            content::handle_read_receipt(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::E2eeDmKeyExchange => {
            e2ee::handle_e2ee_key_exchange(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::E2eeDmKeyExchangeAck => {
            e2ee::handle_e2ee_key_exchange_ack(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::E2eeDmMessage => {
            e2ee::handle_e2ee_dm_message(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::E2eeDmHistory => {
            e2ee::handle_e2ee_dm_history(
                ctx.stream, ctx.seq, session_id, payload, ctx.crypto, ctx.state,
            )
            .await?;
        }
        PacketId::Disconnect => debug!("{addr} DISCONNECT"),
        other => debug!("{addr} unhandled {:?}", other),
    }
    Ok(())
}
