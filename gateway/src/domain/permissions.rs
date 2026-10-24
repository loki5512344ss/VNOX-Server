use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Permissions: u64 {
        const CREATE_INVITE    = 1 << 0;
        const KICK_MEMBERS     = 1 << 1;
        const BAN_MEMBERS      = 1 << 2;
        const MANAGE_CHANNELS  = 1 << 3;
        const MANAGE_ROLES     = 1 << 4;
        const MANAGE_GUILD     = 1 << 5;
        const MESSAGE_SEND     = 1 << 6;
        const MESSAGE_MANAGE   = 1 << 7;
        const VOICE_SPEAK      = 1 << 8;
        const VOICE_MUTE       = 1 << 9;
        const VOICE_DEAFEN     = 1 << 10;
        const MANAGE_WEBHOOKS  = 1 << 11;
        const ADMINISTRATOR    = 1 << 63;
    }
}

impl Permissions {
    pub fn has(&self, required: Permissions) -> bool {
        self.contains(required) || self.contains(Permissions::ADMINISTRATOR)
    }

    pub fn from_role_perms(perms: &[u64]) -> Permissions {
        let mut combined = Permissions::empty();
        for &p in perms {
            combined |= Permissions::from_bits_truncate(p);
        }
        combined
    }
}
