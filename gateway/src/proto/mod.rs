mod framing;
mod packet;

pub mod lnex {
    include!(concat!(env!("OUT_DIR"), "/lnex.rs"));
}

pub use lnex::*;

// Re-export everything so `crate::proto::X` works as before
pub use framing::{encode_packet, to_payload};
pub use packet::{ErrorCode, PacketHeader, PacketId, flags};

// ─── Backward-compat type aliases ────────────────────────────────
// Handshake
pub type HelloPayload = Hello;
pub type AuthPayload = Auth;
pub type SessionPayload = Session;

// Keepalive
pub type PingPayload = Ping;
pub type PongPayload = Pong;

// Error / Disconnect
pub type ErrorPayload = Error;
pub type DisconnectPayload = Disconnect;

// Channels
pub type JoinChannelPayload = JoinChannel;
pub type LeaveChannelPayload = LeaveChannel;
pub type ChannelStatePayload = ChannelState;
pub type ChannelCreatePayload = ChannelCreate;
pub type ChannelDeletePayload = ChannelDelete;
pub type ChannelEditPayload = ChannelEdit;
pub type ChannelListPayload = ChannelList;
pub type UserJoinPayload = UserJoin;
pub type UserLeavePayload = UserLeave;

// Chat
pub type ChatMessagePayload = ChatMessage;
pub type ChatHistoryPayload = ChatHistory;
pub type MessageEditPayload = MessageEdit;
pub type MessageDeletePayload = MessageDelete;

// Voice
pub type VoiceStatePayload = VoiceState;

// Guilds
pub type GuildCreatePayload = GuildCreate;
pub type GuildDeletePayload = GuildDelete;
pub type GuildListPayload = GuildList;
pub type GuildMemberJoinPayload = GuildMemberJoin;
pub type GuildMemberLeavePayload = GuildMemberLeave;
pub type GuildMemberKickPayload = GuildMemberKick;
pub type RoleCreatePayload = RoleCreate;
pub type RoleDeletePayload = RoleDelete;
pub type InviteCreatePayload = InviteCreate;
pub type InviteAcceptPayload = InviteAccept;
pub type InviteDeletePayload = InviteDelete;
pub type GuildAuditLogFetchPayload = GuildAuditLogFetch;
pub type AuditLogEntryPayload = AuditLogEntry;
pub type GuildAuditLogPayload = GuildAuditLog;
pub type GuildMemberListFetchPayload = GuildMemberListFetch;
pub type GuildMemberInfoPayload = GuildMemberInfo;
pub type GuildMemberListPayload = GuildMemberList;
pub type RoleAssignPayload = RoleAssign;
pub type GuildRoleListFetchPayload = GuildRoleListFetch;
pub type GuildRoleInfoPayload = GuildRoleInfo;
pub type GuildRoleListPayload = GuildRoleList;

// DMs
pub type DmStartPayload = DmStart;
pub type DmStartResponsePayload = DmStartResponse;
pub type DmMessagePayload = DmMessage;
pub type DmHistoryPayload = DmHistory;
pub type DmReadAckPayload = DmReadAck;

// Friends
pub type FriendRequestPayload = FriendRequest;
pub type FriendAcceptPayload = FriendAccept;
pub type FriendDeclinePayload = FriendDecline;
pub type FriendRemovePayload = FriendRemove;
pub type FriendListPayload = FriendList;
pub type BlockUserPayload = BlockUser;
pub type UnblockUserPayload = UnblockUser;
pub type BlockListPayload = BlockList;
pub type FriendEventPayload = FriendEvent;

// Presence
pub type PresenceUpdatePayload = PresenceUpdate;
pub type PresenceSyncPayload = PresenceSync;
pub type PresenceEventPayload = PresenceEvent;

// Read/typing
pub type ReadReceiptPayload = ReadReceipt;
pub type TypingStartPayload = TypingStart;

// E2EE
pub type E2eeDmKeyExchangePayload = E2eeDmKeyExchange;
pub type E2eeDmKeyExchangeAckPayload = E2eeDmKeyExchangeAck;
pub type E2eeDmMessagePayload = E2eeDmMessage;
pub type E2eeDmHistoryPayload = E2eeDmHistory;

// Response types
pub type ReadReceiptBroadcastPayload = ReadReceiptBroadcast;
pub type UserRoleUpdatePayload = UserRoleUpdate;
pub type TypingBroadcastPayload = TypingBroadcast;
pub type SimpleResponsePayload = SimpleResponse;
