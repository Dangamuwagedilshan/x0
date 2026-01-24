#[cfg(feature = "analytics")]
pub mod analytics;

#[cfg(feature = "compliance")]
pub mod compliance;

#[cfg(feature = "whitelabel")]
pub mod whitelabel;

#[cfg(feature = "sso")]
pub mod sso;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub customer_id: String,
    pub tier: LicenseTier,
    pub features: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_agents: Option<u32>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
}

impl Default for License {
    fn default() -> Self {
        Self::community()
    }
}

impl License {
    pub fn community() -> Self {
        Self {
            customer_id: "community".to_string(),
            tier: LicenseTier::Community,
            features: vec!["core".to_string()],
            expires_at: None,
            max_agents: None,
            signature: String::new(),
        }
    }

    pub fn from_env() -> Self {
        match std::env::var("X0_LICENSE_KEY") {
            Ok(key) => Self::validate_license_key(&key).unwrap_or_else(|_| Self::community()),
            Err(_) => Self::community(),
        }
    }

    pub fn validate_license_key(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Ok(Self::community());
        }

        let parts: Vec<&str> = key.split('_').collect();
        if parts.len() < 4 || parts[0] != "x0" {
            return Err("Invalid license key format".to_string());
        }

        let tier = match parts[1] {
            "pro" => LicenseTier::Pro,
            "ent" => LicenseTier::Enterprise,
            _ => return Err("Unknown license tier".to_string()),
        };

        let features = match tier {
            LicenseTier::Community => vec!["core".to_string()],
            LicenseTier::Pro => vec![
                "core".to_string(),
                "analytics".to_string(),
            ],
            LicenseTier::Enterprise => vec![
                "core".to_string(),
                "analytics".to_string(),
                "compliance".to_string(),
                "whitelabel".to_string(),
                "sso".to_string(),
            ],
        };

        Ok(Self {
            customer_id: parts[2].to_string(),
            tier,
            features,
            expires_at: None,
            max_agents: None,
            signature: parts.get(3).unwrap_or(&"").to_string(),
        })
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        match self.tier {
            LicenseTier::Enterprise => true,
            _ => self.features.contains(&feature.to_string()),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}
