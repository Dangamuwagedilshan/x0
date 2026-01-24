use axum::{
    extract::State,
    http::StatusCode,
    Extension, Json,
};
use bigdecimal::{BigDecimal, ToPrimitive};
use serde_json::json;
use std::str::FromStr;

use crate::{
    models::*,
    auth::AuthenticatedPlatform,
    AppState,
};

pub async fn get_pricing_suggestion(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<PricingSuggestionRequest>,
) -> Result<Json<PricingSuggestionResponse>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!(
        "Getting pricing suggestion for agent {} base_price ${}", 
        request.agent_id,
        request.base_price
    );

    if request.base_price <= 0.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid base price",
                "message": "Base price must be greater than 0"
            })),
        ));
    }

    let base_price_bd: BigDecimal = request.base_price.to_string().parse()
        .map_err(|e| {
            tracing::error!("Failed to parse base_price to BigDecimal: {}", e);
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid base_price format"
            })))
        })?;
    let currency = request.currency.clone().unwrap_or_else(|| "USD".to_string());
    
    let ppp_config = request.ppp_config.clone().unwrap_or_default();

    if !ppp_config.enabled {
        let min_amount = ppp_config.floor_price.unwrap_or((request.base_price * 0.3).max(1.0));
        let max_amount = ppp_config.ceiling_price.unwrap_or(request.base_price * 3.0);
        
        return Ok(Json(PricingSuggestionResponse {
            suggested_amount: request.base_price,
            min_amount,
            max_amount,
            currency,
            reasoning: ppp_config.custom_reasoning.unwrap_or_else(|| "PPP adjustment disabled. Using base price.".to_string()),
            ppp_adjusted: false,
            adjustment_factor: None,
        }));
    }

    let (mut suggested_amount, mut reasoning, ppp_adjusted, mut adjustment_factor) = if let Some(ref profile) = request.user_profile {
        if let Some(ref country_code) = profile.location_country {
            let ppp_result: Option<BigDecimal> = sqlx::query_scalar!(
                "SELECT get_ppp_adjusted_price($1, $2)",
                base_price_bd.clone(),
                country_code.to_uppercase()
            )
            .fetch_one(&state.db)
            .await
            .ok()
            .flatten();

            if let Some(adjusted_price) = ppp_result {
                use bigdecimal::ToPrimitive;
                let suggested = adjusted_price.to_f64().unwrap_or(request.base_price);
                let factor = if request.base_price > 0.0 {
                    suggested / request.base_price
                } else {
                    1.0
                };
                let ppp_adjusted = (factor - 1.0).abs() > 0.001;
                
                (suggested, "Price adjusted for local purchasing power".to_string(), ppp_adjusted, Some(factor))
            } else {
                (request.base_price, "Using base price".to_string(), false, None)
            }
        } else {
            (request.base_price, "No location data available. Using base price.".to_string(), false, None)
        }
    } else {
        (request.base_price, "No user profile provided. Using base price.".to_string(), false, None)
    };

    let mut config_adjustments: Vec<String> = Vec::new();
    
    if let (Some(min_factor), Some(factor)) = (ppp_config.min_factor, adjustment_factor) {
        if factor < min_factor {
            adjustment_factor = Some(min_factor);
            suggested_amount = request.base_price * min_factor;
            config_adjustments.push(format!("Factor floored at {:.0}%", min_factor * 100.0));
        }
    }
    
    if let (Some(max_factor), Some(factor)) = (ppp_config.max_factor, adjustment_factor) {
        if factor > max_factor {
            adjustment_factor = Some(max_factor);
            suggested_amount = request.base_price * max_factor;
            config_adjustments.push(format!("Factor capped at {:.0}%", max_factor * 100.0));
        }
    }
    
    if let Some(max_discount) = ppp_config.max_discount_percent {
        let min_allowed_price = request.base_price * (1.0 - max_discount / 100.0);
        if suggested_amount < min_allowed_price {
            suggested_amount = min_allowed_price;
            adjustment_factor = Some(1.0 - max_discount / 100.0);
            config_adjustments.push(format!("Max discount {:.0}% applied", max_discount));
        }
    }
    
    if let Some(extra_discount) = ppp_config.extra_discount_percent {
        let discount_multiplier = 1.0 - (extra_discount / 100.0);
        suggested_amount *= discount_multiplier;
        if let Some(factor) = adjustment_factor {
            adjustment_factor = Some(factor * discount_multiplier);
        }
        config_adjustments.push(format!("Extra {:.0}% discount applied", extra_discount));
    }
    
    if let Some(floor) = ppp_config.floor_price {
        if suggested_amount < floor {
            suggested_amount = floor;
            config_adjustments.push(format!("Floor price ${:.2} applied", floor));
        }
    }
    
    if let Some(ceiling) = ppp_config.ceiling_price {
        if suggested_amount > ceiling {
            suggested_amount = ceiling;
            config_adjustments.push(format!("Ceiling price ${:.2} applied", ceiling));
        }
    }
    
    if !config_adjustments.is_empty() {
        reasoning = format!("{} [{}]", reasoning, config_adjustments.join(", "));
    }
    
    if let Some(custom) = &ppp_config.custom_reasoning {
        reasoning = format!("{} {}", custom, reasoning);
    }

    let min_amount = ppp_config.floor_price.unwrap_or((suggested_amount * 0.3).max(1.0));
    let max_amount = ppp_config.ceiling_price.unwrap_or(suggested_amount * 3.0);

    let final_reasoning = if let Some(ref profile) = request.user_profile {
        if let Some(ref context) = profile.context {
            if context.contains("first-time") || context.contains("new") {
                format!("{} First-time user discount applied.", reasoning)
            } else if context.contains("loyal") || context.contains("returning") {
                format!("{} Thank you for your continued support!", reasoning)
            } else {
                reasoning
            }
        } else {
            reasoning
        }
    } else {
        reasoning
    };

    let user_wallet = request.user_profile
        .as_ref()
        .and_then(|_p| Some(""))
        .unwrap_or("");

    let user_country = request.user_profile
        .as_ref()
        .and_then(|p| p.location_country.clone())
        .unwrap_or_default();

    let suggested_bd: BigDecimal = suggested_amount.to_string().parse()
        .map_err(|e| {
            tracing::error!("Failed to parse suggested_amount to BigDecimal: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to calculate dynamic pricing"
            })))
        })?;
    
    sqlx::query!(
        r#"
        INSERT INTO pricing_suggestions (
            platform_id, agent_id, product_id, base_price,
            suggested_price, user_wallet, user_country_code,
            ppp_factor, reasoning, adjustment_type
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )
        "#,
        platform.platform_id,
        request.agent_id,
        request.product_id,
        base_price_bd,
        suggested_bd,
        if user_wallet.is_empty() { None } else { Some(user_wallet) },
        if user_country.is_empty() { None } else { Some(user_country.as_str()) },
        adjustment_factor.map(|f| BigDecimal::from_str(&f.to_string()).ok()).flatten(),
        final_reasoning.clone(),
        if ppp_adjusted { "ppp" } else { "none" }
    )
    .execute(&state.db)
    .await
    .ok();

    tracing::info!(
        "Pricing suggestion: base=${}, suggested=${}, ppp_adjusted={}, config_applied={}",
        request.base_price,
        suggested_amount,
        ppp_adjusted,
        !config_adjustments.is_empty()
    );

    Ok(Json(PricingSuggestionResponse {
        suggested_amount,
        min_amount,
        max_amount,
        currency,
        reasoning: final_reasoning,
        ppp_adjusted,
        adjustment_factor,
    }))
}

pub async fn get_ppp_factor(
    State(state): State<AppState>,
    Extension(_platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let country_code = request.get("country_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "country_code is required"})),
            )
        })?;

    let ppp_data = sqlx::query!(
        r#"
        SELECT country_code, country_name, ppp_factor, currency_code
        FROM ppp_adjustments
        WHERE country_code = $1
        "#,
        country_code.to_uppercase()
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    if let Some(data) = ppp_data {
        Ok(Json(json!({
            "country_code": data.country_code,
            "country_name": data.country_name,
            "ppp_factor": data.ppp_factor,
            "currency_code": data.currency_code,
            "adjustment_percentage": data.ppp_factor.to_f64().map(|f| f * 100.0)
        })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Country not found",
                "message": format!("No PPP data available for country code: {}", country_code)
            })),
        ))
    }
}

pub async fn list_ppp_factors(
    State(state): State<AppState>,
    Extension(_platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let factors = sqlx::query!(
        r#"
        SELECT country_code, country_name, ppp_factor, currency_code
        FROM ppp_adjustments
        ORDER BY country_name ASC
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    let result: Vec<serde_json::Value> = factors
        .into_iter()
        .map(|f| {
            json!({
                "country_code": f.country_code,
                "country_name": f.country_name,
                "ppp_factor": f.ppp_factor,
                "currency_code": f.currency_code,
                "adjustment_percentage": f.ppp_factor.to_f64().map(|v| v * 100.0)
            })
        })
        .collect();

    Ok(Json(json!({
        "total": result.len(),
        "factors": result
    })))
}
