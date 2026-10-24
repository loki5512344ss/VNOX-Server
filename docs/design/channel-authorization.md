# Channel and role authorization

Channel create, edit and delete require guild ownership or actual current guild membership with `MANAGE_CHANNELS`. A stale role assignment does not substitute for membership. Client-supplied guild IDs cannot authorize modification of a channel in another guild: edit/delete use the channel's persisted scope. Global/default channels have no modeled server-administrator account and cannot be mutated through these authenticated user operations. Operators configure them server-side.

The channel list exposes global channels and only those guild channels where the requester is a member. Member and role lists also require current membership.

Role management requires `MANAGE_ROLES`, membership and a role belonging to that same guild. Assignment/removal requires the target to be a current guild member. A role manager may grant or manage only permissions they hold; guild owners and administrators bypass that subset check. This prevents a limited role manager from assigning the owner's administrative role or creating an administrator role. Permission queries additionally join on matching role/assignment guild IDs, so legacy invalid cross-guild assignments cannot supply permissions.

Access mutations take the gateway's shared access write lease. Joins and media authorization take a read lease through their state transition. No client socket write holds this lease. This orders membership/permission removal against issuance of fresh room credentials.

Deleting a channel clears active text/voice subscriptions, revokes the in-process UDP credentials and closes screen-share ownership/subscriptions before removing cached channel metadata. Removing `VOICE_SPEAK` through role deletion/unassignment rechecks active voice sessions and revokes their credentials and screen shares if no remaining role or owner status supplies permission. Voice reconnection requires fresh authorization.

This policy currently applies within one gateway process. It does not claim distributed locking across multiple gateways sharing a database. Existing queued delivery and in-flight network traffic obey the documented delivery-time checks and cannot be recalled after transmission.
