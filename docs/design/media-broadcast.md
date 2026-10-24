# Authenticated screen broadcast, LNEx media extension

The gateway authorizes signalling; established WebRTC transports media directly
between consenting clients (ICE + DTLS-SRTP, VP8 video and separate Opus audio).
An initial publisher has at most four viewers. This mesh is deliberately bounded;
an SFU can replace it later inside the combined daemon. No custom packet crypto,
UDP video fragmentation, global discovery signalling endpoint, or separate voice
machine is introduced.

## Wire contract

The existing authenticated/encrypted LNEx connection carries protobuf packets
`MediaControl` (0x0180, client→gateway) and `MediaEvent` (0x0181, gateway→client).
Control fields: action(1), channel_id(2), share_id(3), target_session_id(4), body(5),
mline_index(6), application_audio(7), microphone(8). Event has identical fields,
plus server-stamped sender_session_id(9), publisher_user_id(10). Strings are UTF-8;
share_id is a UUID and target_session_id is a server session identifier. Actions:
START=1, STOP=2, WATCH=3, UNWATCH=4, OFFER=5, ANSWER=6, ICE=7.

START creates one live share per publisher session; its ack and announcement
carry the authenticated publisher identity and track manifest. WATCH is explicit
receiver consent and authorizes only that viewer/publisher pair. The publisher
then sends OFFER; the viewer replies ANSWER; both may send ICE. SDP is limited to
64 KiB and candidates to 2 KiB; no media bytes travel in these packets. The
server never trusts a client-supplied sender, publisher identity, room membership,
or subscription. Clients ignore ICE/answers not matching a live authorized peer.

Every operation requires authenticated membership in the exact voice channel.
START additionally checks voice-speaking permissions. Guild membership is
revalidated; stale roles do not grant access. Off-channel, unknown-share,
non-owner STOP, unsolicited offers/answers and unsubscribed ICE are rejected.
Channel leave, kick and disconnect revoke shares/subscriptions and emit STOP or
UNWATCH. A viewer's connection is closed on revoke; revocation does not pretend
to erase media already received. Control uses a per-session token bucket of 20 messages/s with a burst of 64;
its entry is removed on revoke/disconnect. Recipient counts are bounded.

## Client media and explicit consent

A local portal-approved capture may be published only after a separate user
start action. Video, selected application/output audio and microphone have
independent track IDs and are not mixed. Missing application audio is an error;
it never enables system audio. The microphone follows existing mute permission
and remains disabled unless separately requested. Receiver viewing is opt-in;
video is rendered in memory, audio uses the selected voice output, and closing
stops peer pipelines. Stop closes every peer, clears frames and sends STOP.

GStreamer webrtcbin provides SDP/ICE/DTLS/SRTP; installed codec/plugin capability
is checked before starting. Host candidates work on reachable networks; optional
administrator-configured STUN/TURN is needed across some NATs. No public relay or
third-party STUN destination is silently chosen. Synthetic two-peer tests must
prove decoded video and distinct application/microphone samples reach the peer;
private desktop/audio capture is never part of automated verification.
