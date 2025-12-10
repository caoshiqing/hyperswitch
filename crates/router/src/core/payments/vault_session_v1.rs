use crate::{
    core::{
        errors::{self, RouterResult},
        payments::{
            flows::{ConstructFlowSpecificData, Feature},
            helpers,
            OperationSessionGetters, OperationSessionSetters,
        },
    },
    routes::{SessionState},
    services::{self},
    types::{
        self as router_types,
        api::{self, enums as api_enums},
        domain,
    },
};
use error_stack::ResultExt;
pub use hyperswitch_domain_models::{
    mandates::MandateData,
    payment_address::PaymentAddress,
    payments::HeaderPayload,
    router_data::{PaymentMethodToken, RouterData},
    router_data_v2::{flow_common_types::VaultConnectorFlowData, RouterDataV2},
    router_flow_types::ExternalVaultCreateFlow,
    router_request_types::CustomerDetails,
    types::{VaultRouterData, VaultRouterDataV2},
};
use router_env::Env;
use std::str::FromStr;

#[allow(clippy::too_many_arguments)]
pub async fn populate_vault_session_details<F, RouterDReq, D>(
    state: &SessionState,
    customer: &Option<domain::Customer>,
    platform: &domain::Platform,
    profile: &domain::Profile,
    payment_data: &mut D,
    key_store: &domain::MerchantKeyStore,
    header_payload: HeaderPayload,
) -> RouterResult<()>
where
    F: Send + Clone + Sync,
    RouterDReq: Send + Sync,

// To create connector flow specific interface data
    D: OperationSessionGetters<F> + OperationSessionSetters<F> + Send + Sync + Clone,
    D: ConstructFlowSpecificData<F, RouterDReq, crate::types::PaymentsResponseData>,
    RouterData<F, RouterDReq, crate::types::PaymentsResponseData>: Feature<F, RouterDReq> + Send,
// To construct connector flow specific api
    dyn api::Connector:
    services::api::ConnectorIntegration<F, RouterDReq, crate::types::PaymentsResponseData>,
{
    let is_external_vault_sdk_enabled = profile.external_vault_details.is_external_vault_enabled();

    if is_external_vault_sdk_enabled {


        let external_vault_source = profile.external_vault_details.get_connector_details()
            .map(|details| &details.vault_connector_id);

        let merchant_connector_account = helpers::get_merchant_connector_account_v1(
            state,
            key_store,
            &profile.merchant_id,
            external_vault_source,
        ).await?;


        let vault_session_details = generate_vault_session_details(
            state,
            platform,
            &merchant_connector_account,
            payment_data.get_connector_customer_id(),
        )
            .await?;

        payment_data.set_vault_session_details(vault_session_details);
    }
    Ok(())
}

pub async fn generate_vault_session_details(
    state: &SessionState,
    platform: &domain::Platform,
    merchant_connector_account: &domain::MerchantConnectorAccount,
    connector_customer_id: Option<String>,
) -> RouterResult<Option<api::VaultSessionDetails>> {
    let connector_name = merchant_connector_account
        .get_connector_name_as_string();

    let connector = api_enums::VaultConnectors::from_str(&connector_name)
        .change_context(errors::ApiErrorResponse::InternalServerError)?;
    let connector_auth_type: router_types::ConnectorAuthType = merchant_connector_account
        .get_connector_account_details()
        .map_err(|err| {
            err.change_context(errors::ApiErrorResponse::InternalServerError)
                .attach_printable("Failed to parse connector auth type")
        })?;

    match (connector, connector_auth_type) {
        // create session for vgs vault
        (
            api_enums::VaultConnectors::Vgs,
            router_types::ConnectorAuthType::SignatureKey { api_secret, .. },
        ) => {
            let sdk_env = match state.conf.env {
                Env::Sandbox | Env::Development | Env::Integ => "sandbox",
                Env::Production => "live",
            }
                .to_string();
            Ok(Some(api::VaultSessionDetails::Vgs(
                api::VgsSessionDetails {
                    external_vault_id: api_secret,
                    sdk_env,
                },
            )))
        }
        // create session for hyperswitch vault
        (
            api_enums::VaultConnectors::HyperswitchVault,
            router_types::ConnectorAuthType::SignatureKey {
                key1, api_secret, ..
            },
        ) => {
           Ok(None)
        }
        _ => {
            router_env::logger::warn!(
                "External vault session creation is not supported for connector: {}",
                connector_name
            );
            Ok(None)
        }
    }
}