pub mod transformers;

use std::sync::LazyLock;

use common_enums::{enums, CaptureMethod, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
        CreateConnectorCustomer,
    },
    router_request_types::{
        AccessTokenRequestData, ConnectorCustomerData, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData,
        PaymentsSyncData, RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentsResponseData, RefundsResponseData, SupportedPaymentMethods,SupportedPaymentMethodsExt
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, PaymentsSyncRouterData, SetupMandateRouterData,
        RefundSyncRouterData, RefundsRouterData, ConnectorCustomerRouterData, PaymentsCancelRouterData
    },
};
use hyperswitch_domain_models::payments::payment_attempt::PaymentAttempt;
use hyperswitch_domain_models::router_response_types::PaymentMethodDetails;
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorSpecifications,
        ConnectorValidation,
    },
    configs::Connectors,errors,events::connector_api_logs::ConnectorEvent,
    types::{self, Response}, webhooks
};
use hyperswitch_interfaces::api::CurrencyUnit;
use hyperswitch_interfaces::consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE};
use hyperswitch_interfaces::types::{ConnectorCustomerType, PaymentsVoidType, RefundSyncType, SetupMandateType};
use masking::{ExposeInterface, Mask, Maskable};
use transformers as axia;

use crate::{
    constants::headers,
    types::{
        ResponseRouterData
    },
    utils::{
        self as connector_utils,PaymentMethodDataType
    }
};
use crate::constants::headers::CONTENT_TYPE;

#[derive(Clone)]
pub struct Axia {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Axia {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }
}

impl api::Payment for Axia {}
impl api::PaymentSession for Axia {}
impl api::ConnectorAccessToken for Axia {}
impl api::MandateSetup for Axia {}
impl api::PaymentAuthorize for Axia {}
impl api::PaymentSync for Axia {}
impl api::PaymentCapture for Axia {}
impl api::PaymentVoid for Axia {}
impl api::RefundSync for Axia {}
impl api::Refund for Axia{}
impl api::RefundExecute for Axia{}
impl api::PaymentToken for Axia {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Axia
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Axia
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Axia {
    fn id(&self) -> &'static str {
        "axia"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.axia.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = axia::AxiaAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                headers::X_API_KEY_ID.to_string(),
                auth.api_key.expose().into_masked(),
            ),
            (
                headers::X_API_KEY.to_string(),
                auth.key1.expose().into_masked(),
            ),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: axia::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.
                code
                .map(|c|c.to_string())
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: response
                .verbiage
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        })
    }
}

impl ConnectorValidation for Axia {
    fn validate_mandate_payment(
        &self,
        pm_type: Option<PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        let mandate_supported_pmd = std::collections::HashSet::from([
            PaymentMethodDataType::Card,
        ]);
        connector_utils::is_mandate_supported(pm_data,pm_type,mandate_supported_pmd,self.id())
    }

    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}


impl api::ConnectorCustomer for Axia {}

impl ConnectorIntegration<CreateConnectorCustomer, ConnectorCustomerData, PaymentsResponseData>
for Axia
{
    fn get_headers(&self,
                   req: &ConnectorCustomerRouterData,
                   _connectors: &Connectors
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            ConnectorCustomerType::get_content_type(self)
                .to_string()
                .into()
        )];

        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(&self,
               _req: &ConnectorCustomerRouterData,
               connectors: &Connectors
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "api/v2/customer"))
    }

    fn get_request_body(&self,
                        req: &ConnectorCustomerRouterData,
                        _connectors: &Connectors
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = axia::CustomerRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(&self,
                     req: &ConnectorCustomerRouterData,
                     connectors: &Connectors
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&ConnectorCustomerType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(ConnectorCustomerType::get_headers(self, req, connectors)?)
                .set_body(ConnectorCustomerType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(&self,
                       data: &ConnectorCustomerRouterData,
                       event_builder: Option<&mut ConnectorEvent>,
                       res: Response
    ) -> CustomResult<ConnectorCustomerRouterData, errors::ConnectorError>
    where
        PaymentsResponseData: Clone,
    {
        let response: axia::AxiaCustomerResponse = res
            .response
            .parse_struct("AxiaCustomerResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res,event_builder)
    }
}
impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Axia {
    //TODO: implement sessions flow
}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Axia {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}api/v2/vault/account",self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &SetupMandateRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = axia::AxiaZeroMandateRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &SetupMandateRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&SetupMandateType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(SetupMandateType::get_headers(self, req, connectors)?)
                .set_body(SetupMandateType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &SetupMandateRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<SetupMandateRouterData, errors::ConnectorError> {
        let response: axia::AxiaSetupMandateResponse = res
            .response
            .parse_struct("AxiaSetupMandateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData{
            response,
            data: data.clone(),
            http_code: res.status_code
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res,event_builder)
    }
}


#[async_trait::async_trait]
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{}",self.base_url(connectors),"api/v2/transaction/purchase"))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = connector_utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let connector_req = axia::TransactionPurchaseRequest::try_from((req,amount))?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: axia::TransactionResponse = res
            .response
            .parse_struct("TransactionResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url method".to_string()).into())
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        _data: &PaymentsSyncRouterData,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
       todo!()
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url method".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body method".to_string()).into())
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsCaptureType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCaptureType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        _data: &PaymentsCaptureRouterData,
        _event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<PaymentsCaptureRouterData, errors::ConnectorError> {
      todo!()
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}api/v2/transaction/{}/void", self.base_url(connectors), req.request.connector_transaction_id))
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Delete)
            .url(&PaymentsVoidType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PaymentsVoidType::get_headers(self,req,connectors)?)
            .set_body(PaymentsVoidType::get_request_body(self,req,connectors)?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        let response: axia::TransactionResponse =
            res.response
                .parse_struct("axia TransactionResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}


impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Axia {
    fn get_headers(
        &self,
        req: &RefundsRouterData<RSync>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<RSync>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let ttid = req.request.connector_transaction_id.clone();
        Ok(format!("{}api/v2/transaction/{}/refund",self.base_url(connectors),ttid))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<RSync>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefundSyncType::get_headers(self, req, connectors)?)
                .set_body(RefundSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn get_request_body(&self,
                        req: &RefundsRouterData<RSync>,
                        _connectors: &Connectors
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let refund_amount = connector_utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;

        Ok(RequestContent::Json(Box::new(axia::RefundRequest::try_from((
            req,
            refund_amount,
        ))?)))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<RSync>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: axia::TransactionResponse =
            res.response
                .parse_struct("axia TransactionResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Axia {

}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Axia {
    fn get_webhook_object_reference_id(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_event_type(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_resource_object(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }
}

static AXIA_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(||{
        let default_capture_methods = vec![
            CaptureMethod::Automatic,
            CaptureMethod::Manual,
            CaptureMethod::SequentialAutomatic,
        ];
        let mut axia_supported_payment_methods = SupportedPaymentMethods::new();
        let supported_card_network = vec![
            common_enums::CardNetwork::Visa,
            common_enums::CardNetwork::Mastercard,
            common_enums::CardNetwork::AmericanExpress,
            common_enums::CardNetwork::Discover,
            common_enums::CardNetwork::JCB,
            common_enums::CardNetwork::DinersClub,
            common_enums::CardNetwork::UnionPay,
        ];

        axia_supported_payment_methods.add(
            common_enums::PaymentMethod::Card,
            PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: common_enums::FeatureStatus::Supported,
                refunds: common_enums::FeatureStatus::Supported,
                supported_capture_methods: default_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card(
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        },
                    ),
                ),
            },
        );

        axia_supported_payment_methods.add(
            common_enums::PaymentMethod::Card,
            PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: common_enums::FeatureStatus::Supported,
                refunds: common_enums::FeatureStatus::Supported,
                supported_capture_methods: default_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card(
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        },
                    ),
                ),
            },
        );
        axia_supported_payment_methods
    });

static AXIA_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Axia",
    description: "Axia connector",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Live,
};

static AXIA_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 0] = [];

impl ConnectorSpecifications for Axia {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&AXIA_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*AXIA_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&AXIA_SUPPORTED_WEBHOOK_FLOWS)
    }
    fn should_call_connector_customer(&self, _payment_attempt: &PaymentAttempt) -> bool {
        false
    }

}
