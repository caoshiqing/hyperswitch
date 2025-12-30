use common_enums::enums;
use common_utils::pii;
use common_utils::types::StringMajorUnit;
use api_models::{self, enums as api_enums};
use hyperswitch_domain_models::{
    payment_method_data::{
        Card, ExternalVaultCard, PaymentMethodData,
    },
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{RSync},
    router_request_types::ResponseId,
    router_response_types::{
        ConnectorCustomerResponseData, PaymentsResponseData, RefundsResponseData,
    },
    types::{ConnectorCustomerRouterData, PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::{consts,errors::ConnectorError};
use masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::{ fmt::Debug, ops::Deref};
use std::collections::HashMap;
use serde_json::Value;
use crate::{
    types::{
        RefundsResponseRouterData, ResponseRouterData
    },
    utils::{
        is_payment_failure, get_unimplemented_payment_method_error_message,CardData,is_refund_failure,RouterData as OtherRouterData
    },
};


#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Flags {
    #[serde(rename = "TAXEXEMPT")]
    Taxexempt,
    #[serde(rename = "EMAIL_RECEIPT_RECURRING")]
    EmailReceiptRecurring,
}


#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString
)]
pub enum Code {
    #[serde(rename = "AUTH")]
    Auth,
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "DUPL")]
    Dupl,
    #[serde(rename = "PKUP")]
    Pkup,
    #[serde(rename = "RETRY")]
    Retry,
    #[serde(rename = "SETUP")]
    Setup,
    #[serde(rename = "TIMEOUT")]
    Timeout,
}

impl Default for Code {
    fn default() -> Code {
        Self::Auth
    }
}
/// Detailed result code specific to internal checks  Values:  * `INT_SUCCESS` - All local System tests passed * `UNKNOWN` - Unknown. Could be pass or fail * `INT_GENERICFAIL` - Generic undefined failure * `ACCT_AUTHFAILED` - Either the username or password sent was invalid * `ACCT_DISABLED` - Account is disabled * `ACCT_SSLCERT` - SSL Certificate check failed * `ACCT_PASSEXPIRED` - Password reached expiration * `ACCT_TOOMANYATTEMPTS` - Too many bad login attempts * `ACCT_INVALIDTRANS` - Invalid transaction type for user * `ACCT_TRANSNOTALLOWED` - User does not have permission for transaction type * `ACCT_TRANSNOTALLOWED_PORT` - Admin or user level transactions are not allowed to be run on specified port * `ACCT_MFA_REQUIRED` - Multi Factor Authentication code required but not provided * `ACCT_MFA_INVALID` - Multi Factor Authentication code is invalid * `AUTH_MFA_GENERATE` - Mannot continue without generating a new Multi Factor Authentication code * `SETUP_SCHED` - Transaction could not be scheduled * `SETUP_CARDTYPE` - Card type not in setup * `SETUP_TRANTYPE` - Transaction type not supported for merchant * `SETUP_DATA` - Generic setup issue * `DATA_BADTRANS` - Bad transaction structure/data/unrecognized * `DATA_ACCOUNT` - Bad account number * `DATA_EXPDATE` - Bad expiration date * `DATA_AMOUNT` - Bad amount * `DATA_TRACKDATA` - Bad track data * `DATA_MICR` - Invalid MICR data, or no MICR sent when required * `DATA_ABAROUTE` - Invalid ABAROUTE specified * `DATA_NOOPENBATCHES` - No open Batches/Batch not found * `DATA_BATCHLOCKED` - Batch has been locked * `DATA_RECORDNOTFOUND` - Record not found * `DATA_INVALIDMOD` - Invalid modification to existing transaction * `DATA_NOCHANGES` - An edit was requested but there were no changes * `DATA_V8EMULATION` - Error evaluating V8 Emulation * `CONN_TOREVERSAL` - TOReversal must be issued. Status of transaction received unknown * `CONN_MAXSENDS` - Maximum send attempts reached * `CONN_MAXATTEMPTS` - Maximum attempts to connect to processor reached * `SYS_SHUTDOWN` - Shutdown being attempted * `SYS_MAINTENANCE` - Transaction type not allowed in maintenance mode * `LIC_USERS` - Max licensed user accounts reached * `LIC_CARDTYPE` - License does not allow that card type * `LIC_TRANEXCEED` - License Transaction Limit has been exceeded * `DB_FAIL` - Failure to write to the System database * `FRAUDAUTODENY` - Auto-denied transaction due to fraud rule * `NSFAUTODENY` - Transaction automatically denied due to insufficient funds when the merchant did not allow partial approvals * `CARDDENYLIST` - Decline due to presence on the card deny list * `ACHVERIFYDENY` - Transaction rejected by ACH verification service * `DATA_3DSMISSING` - Missing required 3DS data

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString
)]
#[strum(serialize_all = "snake_case")]
pub enum MsoftCode {
    #[serde(rename = "INT_SUCCESS")]
    IntSuccess,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "INT_GENERICFAIL")]
    IntGenericfail,
    #[serde(rename = "ACCT_AUTHFAILED")]
    AcctAuthfailed,
    #[serde(rename = "ACCT_DISABLED")]
    AcctDisabled,
    #[serde(rename = "ACCT_SSLCERT")]
    AcctSslcert,
    #[serde(rename = "ACCT_PASSEXPIRED")]
    AcctPassexpired,
    #[serde(rename = "ACCT_TOOMANYATTEMPTS")]
    AcctToomanyattempts,
    #[serde(rename = "ACCT_INVALIDTRANS")]
    AcctInvalidtrans,
    #[serde(rename = "ACCT_TRANSNOTALLOWED")]
    AcctTransnotallowed,
    #[serde(rename = "ACCT_TRANSNOTALLOWED_PORT")]
    AcctTransnotallowedPort,
    #[serde(rename = "ACCT_MFA_REQUIRED")]
    AcctMfaRequired,
    #[serde(rename = "ACCT_MFA_INVALID")]
    AcctMfaInvalid,
    #[serde(rename = "AUTH_MFA_GENERATE")]
    AuthMfaGenerate,
    #[serde(rename = "SETUP_SCHED")]
    SetupSched,
    #[serde(rename = "SETUP_CARDTYPE")]
    SetupCardtype,
    #[serde(rename = "SETUP_TRANTYPE")]
    SetupTrantype,
    #[serde(rename = "SETUP_DATA")]
    SetupData,
    #[serde(rename = "DATA_BADTRANS")]
    DataBadtrans,
    #[serde(rename = "DATA_ACCOUNT")]
    DataAccount,
    #[serde(rename = "DATA_EXPDATE")]
    DataExpdate,
    #[serde(rename = "DATA_AMOUNT")]
    DataAmount,
    #[serde(rename = "DATA_TRACKDATA")]
    DataTrackdata,
    #[serde(rename = "DATA_MICR")]
    DataMicr,
    #[serde(rename = "DATA_ABAROUTE")]
    DataAbaroute,
    #[serde(rename = "DATA_NOOPENBATCHES")]
    DataNoopenbatches,
    #[serde(rename = "DATA_BATCHLOCKED")]
    DataBatchlocked,
    #[serde(rename = "DATA_RECORDNOTFOUND")]
    DataRecordnotfound,
    #[serde(rename = "DATA_INVALIDMOD")]
    DataInvalidmod,
    #[serde(rename = "DATA_NOCHANGES")]
    DataNochanges,
    #[serde(rename = "DATA_V8EMULATION")]
    DataV8Emulation,
    #[serde(rename = "CONN_TOREVERSAL")]
    ConnToreversal,
    #[serde(rename = "CONN_MAXSENDS")]
    ConnMaxsends,
    #[serde(rename = "CONN_MAXATTEMPTS")]
    ConnMaxattempts,
    #[serde(rename = "SYS_SHUTDOWN")]
    SysShutdown,
    #[serde(rename = "SYS_MAINTENANCE")]
    SysMaintenance,
    #[serde(rename = "LIC_USERS")]
    LicUsers,
    #[serde(rename = "LIC_CARDTYPE")]
    LicCardtype,
    #[serde(rename = "LIC_TRANEXCEED")]
    LicTranexceed,
    #[serde(rename = "DB_FAIL")]
    DbFail,
    #[serde(rename = "FRAUDAUTODENY")]
    Fraudautodeny,
    #[serde(rename = "NSFAUTODENY")]
    Nsfautodeny,
    #[serde(rename = "CARDDENYLIST")]
    Carddenylist,
    #[serde(rename = "ACHVERIFYDENY")]
    Achverifydeny,
    #[serde(rename = "DATA_3DSMISSING")]
    Data3Dsmissing,
}

impl Default for MsoftCode {
    fn default() -> MsoftCode {
        Self::IntSuccess
    }
}


//TODO: Fill the struct with respective fields
pub struct AxiaRouterData<T> {
    pub amount: StringMajorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// General result code  Values:  * `AUTH` - Transaction authorized/approved * `SUCCESS` - Operation was successful. Used for internal actions such as report generation * `CALL` - Call processor for authorization * `DENY` - Transaction denied, permanent denial, not likely to succeed on further attempts * `DUPL` - Duplicate transaction * `PKUP` - Confiscate card * `RETRY` - Temporary error, retrying the transaction may yield a different result. Typically these are clerk-initiated retries, not automated * `SETUP` - Setup error * `TIMEOUT` - Transaction not processed in allocated amount of time
    #[serde(rename = "code", skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// Detailed result code specific to internal checks  Values:  * `INT_SUCCESS` - All local System tests passed * `UNKNOWN` - Unknown. Could be pass or fail * `INT_GENERICFAIL` - Generic undefined failure * `ACCT_AUTHFAILED` - Either the username or password sent was invalid * `ACCT_DISABLED` - Account is disabled * `ACCT_SSLCERT` - SSL Certificate check failed * `ACCT_PASSEXPIRED` - Password reached expiration * `ACCT_TOOMANYATTEMPTS` - Too many bad login attempts * `ACCT_INVALIDTRANS` - Invalid transaction type for user * `ACCT_TRANSNOTALLOWED` - User does not have permission for transaction type * `ACCT_TRANSNOTALLOWED_PORT` - Admin or user level transactions are not allowed to be run on specified port * `ACCT_MFA_REQUIRED` - Multi Factor Authentication code required but not provided * `ACCT_MFA_INVALID` - Multi Factor Authentication code is invalid * `AUTH_MFA_GENERATE` - Mannot continue without generating a new Multi Factor Authentication code * `SETUP_SCHED` - Transaction could not be scheduled * `SETUP_CARDTYPE` - Card type not in setup * `SETUP_TRANTYPE` - Transaction type not supported for merchant * `SETUP_DATA` - Generic setup issue * `DATA_BADTRANS` - Bad transaction structure/data/unrecognized * `DATA_ACCOUNT` - Bad account number * `DATA_EXPDATE` - Bad expiration date * `DATA_AMOUNT` - Bad amount * `DATA_TRACKDATA` - Bad track data * `DATA_MICR` - Invalid MICR data, or no MICR sent when required * `DATA_ABAROUTE` - Invalid ABAROUTE specified * `DATA_NOOPENBATCHES` - No open Batches/Batch not found * `DATA_BATCHLOCKED` - Batch has been locked * `DATA_RECORDNOTFOUND` - Record not found * `DATA_INVALIDMOD` - Invalid modification to existing transaction * `DATA_NOCHANGES` - An edit was requested but there were no changes * `DATA_V8EMULATION` - Error evaluating V8 Emulation * `CONN_TOREVERSAL` - TOReversal must be issued. Status of transaction received unknown * `CONN_MAXSENDS` - Maximum send attempts reached * `CONN_MAXATTEMPTS` - Maximum attempts to connect to processor reached * `SYS_SHUTDOWN` - Shutdown being attempted * `SYS_MAINTENANCE` - Transaction type not allowed in maintenance mode * `LIC_USERS` - Max licensed user accounts reached * `LIC_CARDTYPE` - License does not allow that card type * `LIC_TRANEXCEED` - License Transaction Limit has been exceeded * `DB_FAIL` - Failure to write to the System database * `FRAUDAUTODENY` - Auto-denied transaction due to fraud rule * `NSFAUTODENY` - Transaction automatically denied due to insufficient funds when the merchant did not allow partial approvals * `CARDDENYLIST` - Decline due to presence on the card deny list * `ACHVERIFYDENY` - Transaction rejected by ACH verification service * `DATA_3DSMISSING` - Missing required 3DS data
    #[serde(rename = "msoft_code", skip_serializing_if = "Option::is_none")]
    pub msoft_code: Option<MsoftCode>,
    /// Textual, human-interpretable response  Meant for clerk display only and should not be machine interpreted.  Verbiage can come from TranSafe or from a processor. Messages are subject to change at any time and cannot be documented.
    #[serde(rename = "verbiage", skip_serializing_if = "Option::is_none")]
    pub verbiage: Option<String>,

}



#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomerRequest {
    /// Merchant profile identifier  User's may have access to run transactions across multiple profiles. This allows the user to specify which profile a given action should apply to.  If not provided the default profile associated with the user will be used. If a default profile is not associated with the user this parameter is mandatory.
    #[serde(rename = "profile_id", skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Display name
    #[serde(rename = "display_name")]
    pub display_name: Option<Secret<String>>,
    /// Company name
    #[serde(rename = "name_company", skip_serializing_if = "Option::is_none")]
    pub name_company: Option<String>,
    /// Name prefix, Mr. Mrs. Ms. Dr...  Free-form field
    #[serde(rename = "name_prefix", skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    /// First name
    #[serde(rename = "name_first", skip_serializing_if = "Option::is_none")]
    pub name_first: Option<String>,
    /// Middle name
    #[serde(rename = "name_middle", skip_serializing_if = "Option::is_none")]
    pub name_middle: Option<String>,
    /// Last name
    #[serde(rename = "name_last", skip_serializing_if = "Option::is_none")]
    pub name_last: Option<String>,
    /// Name suffix, Jr. Sr. III...  Free-form field
    #[serde(rename = "name_suffix", skip_serializing_if = "Option::is_none")]
    pub name_suffix: Option<String>,
    /// Work phone
    #[serde(rename = "phone_work", skip_serializing_if = "Option::is_none")]
    pub phone_work: Option<String>,
    /// Home phone
    #[serde(rename = "phone_home", skip_serializing_if = "Option::is_none")]
    pub phone_home: Option<String>,
    /// Mobile phone
    #[serde(rename = "phone_mobile", skip_serializing_if = "Option::is_none")]
    pub phone_mobile: Option<Secret<String>>,
    /// Fax number
    #[serde(rename = "phone_fax", skip_serializing_if = "Option::is_none")]
    pub phone_fax: Option<String>,
    /// email
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    pub email: Option<pii::Email>,
    /// Website
    #[serde(rename = "website", skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Business ID - FEIN
    #[serde(rename = "business_id", skip_serializing_if = "Option::is_none")]
    pub business_id: Option<String>,
    /// ID used in external accounting system for customer
    #[serde(rename = "accounting_id", skip_serializing_if = "Option::is_none")]
    pub accounting_id: Option<String>,
    /// General free-form information
    #[serde(rename = "notes", skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// flags controlling behavior  Values:  * `TAXEXEMPT` - Customer is non-taxable * `EMAIL_RECEIPT_RECURRING` - Send receipt email for recurring transactions. The following conditions must be met for customers to receive recurring receipt emails. + This flag must be enabled. + Customer must have an email on file. + The merchant profile must have a name configured. + The merchant profile must have a public reply email configured.
    #[serde(rename = "flags", skip_serializing_if = "Option::is_none")]
    pub flags: Option<Flags>,

}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct AxiaCustomerResponse {
    /// General result code  Values:  * `AUTH` - Transaction authorized/approved * `SUCCESS` - Operation was successful. Used for internal actions such as report generation * `CALL` - Call processor for authorization * `DENY` - Transaction denied, permanent denial, not likely to succeed on further attempts * `DUPL` - Duplicate transaction * `PKUP` - Confiscate card * `RETRY` - Temporary error, retrying the transaction may yield a different result. Typically these are clerk-initiated retries, not automated * `SETUP` - Setup error * `TIMEOUT` - Transaction not processed in allocated amount of time
    #[serde(rename = "code", skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// Detailed result code specific to internal checks  Values:  * `INT_SUCCESS` - All local System tests passed * `UNKNOWN` - Unknown. Could be pass or fail * `INT_GENERICFAIL` - Generic undefined failure * `ACCT_AUTHFAILED` - Either the username or password sent was invalid * `ACCT_DISABLED` - Account is disabled * `ACCT_SSLCERT` - SSL Certificate check failed * `ACCT_PASSEXPIRED` - Password reached expiration * `ACCT_TOOMANYATTEMPTS` - Too many bad login attempts * `ACCT_INVALIDTRANS` - Invalid transaction type for user * `ACCT_TRANSNOTALLOWED` - User does not have permission for transaction type * `ACCT_TRANSNOTALLOWED_PORT` - Admin or user level transactions are not allowed to be run on specified port * `ACCT_MFA_REQUIRED` - Multi Factor Authentication code required but not provided * `ACCT_MFA_INVALID` - Multi Factor Authentication code is invalid * `AUTH_MFA_GENERATE` - Mannot continue without generating a new Multi Factor Authentication code * `SETUP_SCHED` - Transaction could not be scheduled * `SETUP_CARDTYPE` - Card type not in setup * `SETUP_TRANTYPE` - Transaction type not supported for merchant * `SETUP_DATA` - Generic setup issue * `DATA_BADTRANS` - Bad transaction structure/data/unrecognized * `DATA_ACCOUNT` - Bad account number * `DATA_EXPDATE` - Bad expiration date * `DATA_AMOUNT` - Bad amount * `DATA_TRACKDATA` - Bad track data * `DATA_MICR` - Invalid MICR data, or no MICR sent when required * `DATA_ABAROUTE` - Invalid ABAROUTE specified * `DATA_NOOPENBATCHES` - No open Batches/Batch not found * `DATA_BATCHLOCKED` - Batch has been locked * `DATA_RECORDNOTFOUND` - Record not found * `DATA_INVALIDMOD` - Invalid modification to existing transaction * `DATA_NOCHANGES` - An edit was requested but there were no changes * `DATA_V8EMULATION` - Error evaluating V8 Emulation * `CONN_TOREVERSAL` - TOReversal must be issued. Status of transaction received unknown * `CONN_MAXSENDS` - Maximum send attempts reached * `CONN_MAXATTEMPTS` - Maximum attempts to connect to processor reached * `SYS_SHUTDOWN` - Shutdown being attempted * `SYS_MAINTENANCE` - Transaction type not allowed in maintenance mode * `LIC_USERS` - Max licensed user accounts reached * `LIC_CARDTYPE` - License does not allow that card type * `LIC_TRANEXCEED` - License Transaction Limit has been exceeded * `DB_FAIL` - Failure to write to the System database * `FRAUDAUTODENY` - Auto-denied transaction due to fraud rule * `NSFAUTODENY` - Transaction automatically denied due to insufficient funds when the merchant did not allow partial approvals * `CARDDENYLIST` - Decline due to presence on the card deny list * `ACHVERIFYDENY` - Transaction rejected by ACH verification service * `DATA_3DSMISSING` - Missing required 3DS data
    #[serde(rename = "msoft_code", skip_serializing_if = "Option::is_none")]
    pub msoft_code: Option<MsoftCode>,
    /// Textual, human-interpretable response  Meant for clerk display only and should not be machine interpreted.  Verbiage can come from TranSafe or from a processor. Messages are subject to change at any time and cannot be documented.
    #[serde(rename = "verbiage", skip_serializing_if = "Option::is_none")]
    pub verbiage: Option<String>,
    /// Customer identifier
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}


impl<T> From<(StringMajorUnit, T)> for AxiaRouterData<T> {
    fn from((amount, item): (StringMajorUnit, T)) -> Self {
        //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data: item,
        }
    }
}


#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct TransactionPurchaseRequest {
    /// Merchant profile identifier  User's may have access to run transactions across multiple profiles. This allows the user to specify which profile a given action should apply to.  If not provided the default profile associated with the user will be used. If a default profile is not associated with the user this parameter is mandatory.
    #[serde(rename = "profile_id", skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(flatten)]
    pub payment_data: Option<AxiaPaymentMethodData>,
    #[serde(rename = "money")]
    pub money: Money,
    #[serde(flatten)]
    pub additional_property:HashMap<String,String>,
    #[serde(rename = "shipping")]
    pub shipping: Option<AxiaShippingAddress>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AxiaPaymentMethodData {
    Card(AxiaCardData),
    VaultCard(AxiaVaultCardData),
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct AxiaCardData {
    #[serde(rename = "verification", skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
    #[serde(rename = "account_data")]
    pub account_data: Option<AxiaAccountData<cards::CardNumber>>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct AxiaVaultCardData {
    #[serde(rename = "verification", skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
    #[serde(rename = "account_data")]
    pub account_data: Option<AxiaAccountData<Secret<String>>>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct AxiaAccountData<T> {
    /// Account number
    #[serde(rename = "account")]
    pub account: T,
    /// Expiration date of the card (MMYY format)
    #[serde(rename = "expdate")]
    pub expdate: Secret<String>,
}


#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Verification {
    #[serde(rename = "cv")]
    pub cv: Secret<String>,
    #[serde(rename = "zip")]
    pub zip: Secret<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct AxiaShippingAddress {
    #[serde(rename = "shipcountry")]
    pub ship_country: Option<api_enums::CountryAlpha2>,
    #[serde(rename = "shipzip")]
    pub ship_zip:Option<Secret<String>>,
}

impl TryFrom<(&PaymentsAuthorizeRouterData,&Card)> for AxiaPaymentMethodData {
    type Error = ConnectorError;

    fn try_from((item,card): (&PaymentsAuthorizeRouterData,&Card)) -> Result<Self, Self::Error> {
        let expdate = card.get_expiry_date_as_mmyy()?;
        let account_data = AxiaAccountData {
            account: card.card_number.clone(),
            expdate: expdate,
        };
        let shipping_zip = item.get_optional_shipping_zip().ok_or_else(|| {
            ConnectorError::MissingRequiredField {
                field_name:"shipping.address.zip"
            }
        })?;
        let verification = Verification {
            cv: card.card_cvc.clone(),
            zip: shipping_zip,
        };
        Ok(Self::Card(AxiaCardData {
            verification: Some(verification),
            account_data: Some(account_data),
        }))
    }
}


impl TryFrom<(&PaymentsAuthorizeRouterData,&ExternalVaultCard)> for AxiaPaymentMethodData {
    type Error = ConnectorError;

    fn try_from((item,card): (&PaymentsAuthorizeRouterData,&ExternalVaultCard)) -> Result<Self, Self::Error> {
        let year = card.card_exp_year
            .peek()
            .get(card.card_exp_year.peek().len().saturating_sub(2)..)
            .ok_or(ConnectorError::RequestEncodingFailed)?
            .to_string();

        // 获取月份（需要格式化为两位）
        let exp_month = card.card_exp_month
            .peek()
            .parse::<u8>()
            .map_err(|_| ConnectorError::InvalidDataFormat {
                field_name: "payment_method_data.card.card_exp_month",
            })?;

        let month = ::cards::CardExpirationMonth::try_from(exp_month)
            .map_err(|_| ConnectorError::InvalidDataFormat {
                field_name: "payment_method_data.card.card_exp_month",
            })?;

        // 拼接为 MMYY 格式
        let expdate = Secret::new(format!("{}{}", month.two_digits(), year));
        let account_data = AxiaAccountData {
            account: card.card_number.clone(),
            expdate: expdate,
        };
        let shipping_zip = item.get_optional_shipping_zip().ok_or_else(|| {
            ConnectorError::MissingRequiredField {
                field_name:"shipping.address.zip"
            }
        })?;
        let verification = Verification {
            cv: card.card_cvc.clone(),
            zip: shipping_zip,
        };
        Ok(Self::VaultCard(AxiaVaultCardData {
            verification: Some(verification),
            account_data: Some(account_data),
        }))
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Money {
    pub amount: StringMajorUnit,
    pub currency: String,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString
)]
pub enum Cardtype {
    #[serde(rename = "VISA")]
    Visa,
    #[serde(rename = "MC")]
    Mc,
    #[serde(rename = "AMEX")]
    Amex,
    #[serde(rename = "DISC")]
    Disc,
    #[serde(rename = "DINERS")]
    Diners,
    #[serde(rename = "JCB")]
    Jcb,
    #[serde(rename = "SWITCH")]
    Switch,
    #[serde(rename = "BML")]
    Bml,
    #[serde(rename = "GIFT")]
    Gift,
    #[serde(rename = "OTHER")]
    Other,
    #[serde(rename = "VISADEBIT")]
    Visadebit,
    #[serde(rename = "MCDEBIT")]
    Mcdebit,
    #[serde(rename = "OTHERDEBIT")]
    Otherdebit,
    #[serde(rename = "VISADS")]
    Visads,
    #[serde(rename = "EBT")]
    Ebt,
    #[serde(rename = "CHECK")]
    Check,
    #[serde(rename = "INTERAC")]
    Interac,
    #[serde(rename = "CUP")]
    Cup,
    #[serde(rename = "PAYPALEC")]
    Paypalec,
    #[serde(rename = "ACH")]
    Ach,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl Default for Cardtype {
    fn default() -> Cardtype {
        Self::Visa
    }
}

#[derive(Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct TransactionResponse {
    /// General result code  Values:  * `AUTH` - Transaction authorized/approved * `SUCCESS` - Operation was successful. Used for internal actions such as report generation * `CALL` - Call processor for authorization * `DENY` - Transaction denied, permanent denial, not likely to succeed on further attempts * `DUPL` - Duplicate transaction * `PKUP` - Confiscate card * `RETRY` - Temporary error, retrying the transaction may yield a different result. Typically these are clerk-initiated retries, not automated * `SETUP` - Setup error * `TIMEOUT` - Transaction not processed in allocated amount of time
    #[serde(rename = "code")]
    pub code: Code,
    /// Detailed result code specific to internal checks  Values:  * `INT_SUCCESS` - All local System tests passed * `UNKNOWN` - Unknown. Could be pass or fail * `INT_GENERICFAIL` - Generic undefined failure * `ACCT_AUTHFAILED` - Either the username or password sent was invalid * `ACCT_DISABLED` - Account is disabled * `ACCT_SSLCERT` - SSL Certificate check failed * `ACCT_PASSEXPIRED` - Password reached expiration * `ACCT_TOOMANYATTEMPTS` - Too many bad login attempts * `ACCT_INVALIDTRANS` - Invalid transaction type for user * `ACCT_TRANSNOTALLOWED` - User does not have permission for transaction type * `ACCT_TRANSNOTALLOWED_PORT` - Admin or user level transactions are not allowed to be run on specified port * `ACCT_MFA_REQUIRED` - Multi Factor Authentication code required but not provided * `ACCT_MFA_INVALID` - Multi Factor Authentication code is invalid * `AUTH_MFA_GENERATE` - Mannot continue without generating a new Multi Factor Authentication code * `SETUP_SCHED` - Transaction could not be scheduled * `SETUP_CARDTYPE` - Card type not in setup * `SETUP_TRANTYPE` - Transaction type not supported for merchant * `SETUP_DATA` - Generic setup issue * `DATA_BADTRANS` - Bad transaction structure/data/unrecognized * `DATA_ACCOUNT` - Bad account number * `DATA_EXPDATE` - Bad expiration date * `DATA_AMOUNT` - Bad amount * `DATA_TRACKDATA` - Bad track data * `DATA_MICR` - Invalid MICR data, or no MICR sent when required * `DATA_ABAROUTE` - Invalid ABAROUTE specified * `DATA_NOOPENBATCHES` - No open Batches/Batch not found * `DATA_BATCHLOCKED` - Batch has been locked * `DATA_RECORDNOTFOUND` - Record not found * `DATA_INVALIDMOD` - Invalid modification to existing transaction * `DATA_NOCHANGES` - An edit was requested but there were no changes * `DATA_V8EMULATION` - Error evaluating V8 Emulation * `CONN_TOREVERSAL` - TOReversal must be issued. Status of transaction received unknown * `CONN_MAXSENDS` - Maximum send attempts reached * `CONN_MAXATTEMPTS` - Maximum attempts to connect to processor reached * `SYS_SHUTDOWN` - Shutdown being attempted * `SYS_MAINTENANCE` - Transaction type not allowed in maintenance mode * `LIC_USERS` - Max licensed user accounts reached * `LIC_CARDTYPE` - License does not allow that card type * `LIC_TRANEXCEED` - License Transaction Limit has been exceeded * `DB_FAIL` - Failure to write to the System database * `FRAUDAUTODENY` - Auto-denied transaction due to fraud rule * `NSFAUTODENY` - Transaction automatically denied due to insufficient funds when the merchant did not allow partial approvals * `CARDDENYLIST` - Decline due to presence on the card deny list * `ACHVERIFYDENY` - Transaction rejected by ACH verification service * `DATA_3DSMISSING` - Missing required 3DS data
    #[serde(rename = "msoft_code", skip_serializing_if = "Option::is_none")]
    pub msoft_code: Option<MsoftCode>,
    /// Textual, human-interpretable response  Meant for clerk display only and should not be machine interpreted.  Verbiage can come from TranSafe or from a processor. Messages are subject to change at any time and cannot be documented.
    #[serde(rename = "verbiage", skip_serializing_if = "Option::is_none")]
    pub verbiage: Option<String>,
   #[serde(rename = "phard_code", skip_serializing_if = "Option::is_none")]
    pub phard_code: Option<PhardCode>,
    /// Currency code for card, if different from default currency of origin country.  ISO 4217 3-digit numeric code
    #[serde(rename = "card_currency", skip_serializing_if = "Option::is_none")]
    pub card_currency: Option<String>,
    /// Visa 2-character or Mastercard 3-character card level
    #[serde(rename = "card_cardlevel", skip_serializing_if = "Option::is_none")]
    pub card_cardlevel: Option<String>,
    /// Country where the card originated  ISO 3166-1 alpha-3 country code
    #[serde(rename = "card_country_code", skip_serializing_if = "Option::is_none")]
    pub card_country_code: Option<String>,
    /// Pipe-delimited list of 2-character debit network codes supported by the card, followed by a `Y` or `N` to indicate if the network is PINless-capable or not.  Example: `19N|14N`
    #[serde(rename = "card_debit_network", skip_serializing_if = "Option::is_none")]
    pub card_debit_network: Option<String>,
    /// If card is an EBT card, the 2-letter state code in which the card was issued
    #[serde(rename = "card_ebt_state", skip_serializing_if = "Option::is_none")]
    pub card_ebt_state: Option<String>,
    /// Name of issuing bank.  Not always available.
    #[serde(rename = "card_issuer_bank", skip_serializing_if = "Option::is_none")]
    pub card_issuer_bank: Option<String>,
    /// Additional processor-provided data returned by some processors that is intended to be printed on receipts. Often used for Gift/Loyalty programs. Please consult with your processor for more information
    #[serde(rename = "printdata", skip_serializing_if = "Option::is_none")]
    pub printdata: Option<String>,
    /// Masked account number
    #[serde(rename = "account", skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Type and/or brand of card presented.  The manner a card was used will impact the card type. For example, A Visa debit card run as credit will return the `cardtype` as `VISA` (credit), not `VISADEBIT`. In some cases, it may not be possible to distinguish a branded debit card as either credit or debit.  The `card_cardclass` response parameter, if present, will provide the class of card. For example, a `VISA` `cardtype` with a `card_cardclass` of `DEBIT` indicates a `VISA` debit card that was run as credit.  Additionally, the `card_funding_source` will provide further information about what type of funds are backing the card.   Values:  * `VISA` - Visa * `MC` - Mastercard * `AMEX` - American Express * `DISC` - Discover * `DINERS` - Diners * `JCB` - Japan Credit Bureau * `SWITCH` - United Kingdom debit card (no longer in use) * `BML` - Bill Me Later * `GIFT` - Generic gift card * `OTHER` - Gift / loyalty * `VISADEBIT` - Visa-branded debit card * `MCDEBIT` - Mastercard-branded debit card * `OTHERDEBIT` - Generic debit card * `VISADS` - Transaction originally ran as Debit, but processor reported back that it was actually run as a credit card (Visa Only) * `EBT` - EBT (Electronic Benefits Transfer -- US food stamps/nutritional assistance) * `CHECK` - Electronic check * `INTERAC` - Canadian debit * `CUP` - China Union Pay * `PAYPALEC` - PayPal Express Checkout * `ACH` - Electronic funds transfer, e.g. CCD,PPD * `UNKNOWN` - Card type is unknown
    #[serde(rename = "cardtype", skip_serializing_if = "Option::is_none")]
    pub cardtype: Option<Cardtype>,
    /// Name of the cardholder. Might not always be present
    #[serde(rename = "cardholdername", skip_serializing_if = "Option::is_none")]
    pub cardholdername: Option<String>,
    /// The time the transaction was processed as a timestamp
    #[serde(rename = "timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Transaction identifier
    #[serde(rename = "ttid")]
    pub ttid: String,
}

/// Detailed result code for success/fail from processor  Used to determine a more detailed reasons for a decline coming from the processor. Only present if a response was or could be received from the processor.  If `code` is `AUTH` and `phard_code` is `SUCCESS`, the processor approved the transaction. If `code` is anything other than `AUTH` which indicates a decline, and `phard_code` is anything other than `UNKNOWN`, then the decline came from the processor.  Some transactions can be eight online or offline (internal) based on the processor. For example, a host based processor may have an adjustment run online and others it might be offline and only sent at settlement. In this case `phard_code` may or may not be returned based on how the transaction is required to be handled.  Not all processors provide detailed reasons as to why a decline was generated. A `GENERICFAIL` value indicates no detailed reason was given. The `verbiage` response parameter may provide more information.  However, typically when a `GENERICFAIL` is received the only way to receive detailed information is by contacting the processor directly.   Values:  * `SUCCESS` - Generic success * `UNKNOWN` - Unknown. Could be pass or fail * `GENERICFAIL` - Generic undefined failure * `CALL` - Call issuer for authorization * `NOREPLY` - No reply from processor backend * `PICKUP_NOFRAUD` - Confiscate card (no fraud assumed) * `PICKUP_FRAUD` - Confiscate card (fraud assumed) * `PICKUP_LOST` - Confiscate card (reported lost) * `PICKUP_STOLEN` - Confiscate card (reported stolen) * `ACCTERROR` - Account number or length error * `ALREADY_REVERSED` - Reversal already issued * `BAD_PIN` - Bad Debit/EBT PIN info * `CASHBACK_EXCEEDED` - Too much cashback * `CASHBACK_NOAVAIL` - Cashback services unavailable * `CID_ERROR` - CVV2/CID error * `DATE_ERROR` - Date error * `DONOTHONOR` - Do not honor card * `INSUFFICIENT_FUNDS` - Insufficient funds * `EXCEED_WITHDRAWAL_LIMIT` - Exceeds withdrawal limit * `INVALID_SERVICE_CODE` - Invalid service code * `EXCEED_ACTIVITY_LIMIT` - Exceeds activity limit * `VIOLATION` - Violation * `ENCRYPTION_ERROR` - Encryption Error (usually debit/ebt) * `CARD_EXPIRED` - Credit card expired * `REENTER` - Bad transaction data or setup, reenter * `SECURITY_VIOLATION` - security violation * `NOT_PERMITTED_CARD` - Card not permitted for this transaction type * `NOT_PERMITTED_TRAN` - Transaction type not permitted for this acct * `SYSTEM_ERROR` - Generic system error * `BAD_MERCH_ID` - Bad merchant ID * `DUPLICATE_BATCH` - Duplicate batch number * `REJECTED_BATCH` - Batch rejected for settlement * `ACCOUNT_CLOSED` - Account closed * `RECURRING_CANCEL` - Recurring Payment Failed and will continue to fail * `ALREADY_ACTIVE` - Gift Card is already activated * `NOT_ACTIVE` - Gift Card has not been activated * `BALANCE_MISMATCH` - Balance Mismatch (settlement totals don't match) * `ID_ERROR` - Valid ID required for transaction * `REPRESENTED` - Represented Check/Transaction * `MANAGER_NEEDED` - Manager needed (velocity warning?) * `INELIGIBLE_CONV` - Check conversion: Auth OK, but check is not eligible for conversion * `RETRY` - Retry the transaction, it is likely that a second attempt will work (e.g. sequence error) * `INVALID_ACCOUNT_TYPE` - For Interac you choose between checking and savings, this indicates the account selected is not set up * `RETRY_FORCE_INSERT` - In some specific cases the issuer may need to indicate that a tap transaction that goes online must be inserted to complete
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString
)]
pub enum PhardCode {
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "GENERICFAIL")]
    Genericfail,
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "NOREPLY")]
    Noreply,
    #[serde(rename = "PICKUP_NOFRAUD")]
    PickupNofraud,
    #[serde(rename = "PICKUP_FRAUD")]
    PickupFraud,
    #[serde(rename = "PICKUP_LOST")]
    PickupLost,
    #[serde(rename = "PICKUP_STOLEN")]
    PickupStolen,
    #[serde(rename = "ACCTERROR")]
    Accterror,
    #[serde(rename = "ALREADY_REVERSED")]
    AlreadyReversed,
    #[serde(rename = "BAD_PIN")]
    BadPin,
    #[serde(rename = "CASHBACK_EXCEEDED")]
    CashbackExceeded,
    #[serde(rename = "CASHBACK_NOAVAIL")]
    CashbackNoavail,
    #[serde(rename = "CID_ERROR")]
    CidError,
    #[serde(rename = "DATE_ERROR")]
    DateError,
    #[serde(rename = "DONOTHONOR")]
    Donothonor,
    #[serde(rename = "INSUFFICIENT_FUNDS")]
    InsufficientFunds,
    #[serde(rename = "EXCEED_WITHDRAWAL_LIMIT")]
    ExceedWithdrawalLimit,
    #[serde(rename = "INVALID_SERVICE_CODE")]
    InvalidServiceCode,
    #[serde(rename = "EXCEED_ACTIVITY_LIMIT")]
    ExceedActivityLimit,
    #[serde(rename = "VIOLATION")]
    Violation,
    #[serde(rename = "ENCRYPTION_ERROR")]
    EncryptionError,
    #[serde(rename = "CARD_EXPIRED")]
    CardExpired,
    #[serde(rename = "REENTER")]
    Reenter,
    #[serde(rename = "SECURITY_VIOLATION")]
    SecurityViolation,
    #[serde(rename = "NOT_PERMITTED_CARD")]
    NotPermittedCard,
    #[serde(rename = "NOT_PERMITTED_TRAN")]
    NotPermittedTran,
    #[serde(rename = "SYSTEM_ERROR")]
    SystemError,
    #[serde(rename = "BAD_MERCH_ID")]
    BadMerchId,
    #[serde(rename = "DUPLICATE_BATCH")]
    DuplicateBatch,
    #[serde(rename = "REJECTED_BATCH")]
    RejectedBatch,
    #[serde(rename = "ACCOUNT_CLOSED")]
    AccountClosed,
    #[serde(rename = "RECURRING_CANCEL")]
    RecurringCancel,
    #[serde(rename = "ALREADY_ACTIVE")]
    AlreadyActive,
    #[serde(rename = "NOT_ACTIVE")]
    NotActive,
    #[serde(rename = "BALANCE_MISMATCH")]
    BalanceMismatch,
    #[serde(rename = "ID_ERROR")]
    IdError,
    #[serde(rename = "REPRESENTED")]
    Represented,
    #[serde(rename = "MANAGER_NEEDED")]
    ManagerNeeded,
    #[serde(rename = "INELIGIBLE_CONV")]
    IneligibleConv,
    #[serde(rename = "RETRY")]
    Retry,
    #[serde(rename = "INVALID_ACCOUNT_TYPE")]
    InvalidAccountType,
    #[serde(rename = "RETRY_FORCE_INSERT")]
    RetryForceInsert,
}

impl Default for PhardCode {
    fn default() -> PhardCode {
        Self::Success
    }
}


impl TryFrom<&ConnectorCustomerRouterData> for CustomerRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: &ConnectorCustomerRouterData) -> Result<Self, Self::Error> {


        Ok(Self {
            profile_id: None,
            notes: item.request.description.to_owned(),
            email: item.request.email.to_owned(),
            website: None,
            business_id: None,
            phone_mobile: item.request.phone.to_owned(),
            display_name: item.request.name.to_owned(),
            name_company: None,
            name_prefix: None,
            name_first: None,
            name_middle: None,
            name_last: None,
            name_suffix: None,
            phone_work: None,
            phone_home: None,
            phone_fax: None,
            accounting_id: None,
            flags: None,
        })
    }
}

impl TryFrom<(&PaymentsAuthorizeRouterData, StringMajorUnit)> for TransactionPurchaseRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        (item, amount): (&PaymentsAuthorizeRouterData, StringMajorUnit)
    ) -> Result<Self, Self::Error> {
        let payment_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                Some(AxiaPaymentMethodData::try_from((item,card))?)
            }
            PaymentMethodData::VaultDataCard(vaultcard) => {
                Some(AxiaPaymentMethodData::try_from((item,vaultcard.deref()))?)
            }
            _ => None,
        };
        if payment_data.is_none() {
            return Err(
                ConnectorError::NotImplemented(get_unimplemented_payment_method_error_message(
                    "axia",
                )).into());
        }
        let order_id = item.connector_request_reference_id.clone();
        let additional_property =
            get_transaction_metadata(item.request.metadata.clone().map(Into::into), order_id);
        let money = Money {
            amount,
            currency: item.request.currency.to_string(),
        };

        let shipping = if let Some(_) = item.get_optional_shipping(){
            Some(AxiaShippingAddress{
                ship_country:item.get_optional_shipping_country(),
                ship_zip:item.get_optional_shipping_zip()
            })
        }else{
            None
        };

        Ok(Self {
            profile_id: None,
            payment_data,
            money,
            additional_property,
            shipping
        })
    }
}


//TODO: Fill the struct with respective fields
// Auth Struct
pub struct AxiaAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) key1: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AxiaAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                key1: key1.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub struct AxiaPaymentStatus(Code, Option<PhardCode>);

impl From<AxiaPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: AxiaPaymentStatus) -> Self {
        match (item.0, item.1) {
            (Code::Auth, Some(phard_code)) => {
                match phard_code {
                    PhardCode::Success => Self::Charged,
                    PhardCode::AlreadyReversed => Self::Voided,
                    _ => Self::Failure
                }
            }
            (_, _) => Self::Failure
        }
    }
}


impl<F, T> TryFrom<ResponseRouterData<F, TransactionResponse, T, PaymentsResponseData>>
for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, TransactionResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let axia_payment_status = AxiaPaymentStatus(item.response.code, item.response.phard_code);
        let status = common_enums::AttemptStatus::from(axia_payment_status);

        let response = if is_payment_failure(status) {
            *get_axia_payments_response_data(
                &item.response,
                item.http_code,
                item.response.ttid.clone(),
            )
        }else{
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ttid.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.ttid),
                incremental_authorization_allowed: None,
                charges: None,
            })
        };

        Ok(Self {
            status,
            response,
            ..item.data
        })
    }
}


impl<F, T> TryFrom<ResponseRouterData<F, AxiaCustomerResponse, T, PaymentsResponseData>>
for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, AxiaCustomerResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::ConnectorCustomerResponse(
                ConnectorCustomerResponseData::new_with_customer_id(item.response.id.unwrap()),
            )),
            ..item.data
        })
    }
}


#[derive(Debug, Serialize)]
pub struct RefundRequest {
    #[serde(rename = "profile_id",skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(rename = "money")]
    pub money: Money,
    #[serde(flatten)]
    pub additional_property:HashMap<String,String>
}

impl<F> TryFrom<(&RefundsRouterData<F>, StringMajorUnit)> for RefundRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        (item, refund_amount): (&RefundsRouterData<F>, StringMajorUnit)
    ) -> Result<Self, Self::Error> {
        let money = Money {
            amount: refund_amount,
            currency: item.request.currency.to_string(),
        };
        let mut additional_property = HashMap::new();
        additional_property.insert(String::from("external_refund_id"), item.request.refund_id.clone());
        Ok(Self {
            money,
            profile_id: None,
            additional_property
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub struct AxiaRefundStatus(Code,Option<PhardCode>);

impl From<AxiaRefundStatus> for enums::RefundStatus {
    fn from(item: AxiaRefundStatus) -> Self {
       match (item.0, item.1) {
           (Code::Auth,Some(phard_code)) => {
               if matches!(phard_code,PhardCode::Success) {
                   Self::Success
               } else {
                   Self::Failure
               }
           }
           (_,_) => Self::Failure
       }
    }
}



impl TryFrom<RefundsResponseRouterData<RSync, TransactionResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, TransactionResponse>,
    ) -> Result<Self, Self::Error> {
        let code = match item.response.phard_code {
            Some(phard_code) => {
                phard_code.to_string()
            }
            None => {
                item.response.code.to_string()
            }
        };
        let axia_refund_status = AxiaRefundStatus(item.response.code,item.response.phard_code);
        let refund_status = enums::RefundStatus::from(axia_refund_status);
        let response = if is_refund_failure(refund_status) {
            Err(hyperswitch_domain_models::router_data::ErrorResponse {
                code,
                message: item.response.verbiage.clone().unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: None,
                status_code:item.http_code,
                attempt_status: None,
                connector_transaction_id:Some(item.response.ttid.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        }else{
            Ok(RefundsResponseData {
                connector_refund_id: item.response.ttid.clone(),
                refund_status,
            })
        };

        Ok(Self {
             response,
            ..item.data
        })
    }
}


fn get_axia_payments_response_data(
    response: &TransactionResponse,
    http_code: u16,
    response_id: String,
) -> Box<Result<PaymentsResponseData, hyperswitch_domain_models::router_data::ErrorResponse>> {
    let code = match response.phard_code {
        Some(phard_code) => {
            phard_code.to_string()
        }
        None => {
            response.code.to_string()
        }
    };
    Box::new(Err(hyperswitch_domain_models::router_data::ErrorResponse {
        code,
        message: response.verbiage.clone().unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
        reason: None,
        status_code:http_code,
        attempt_status: None,
        connector_transaction_id:Some(response_id),
        network_decline_code: None,
        network_advice_code: None,
        network_error_message: None,
        connector_metadata: None,
    }))
}


fn get_transaction_metadata(
    merchant_metadata: Option<Secret<Value>>,
    order_id: String,
) -> HashMap<String, String> {
    let mut meta_data = HashMap::from([("external_order_id".to_string(), order_id)]);
    let mut request_hash_map = HashMap::new();

    if let Some(metadata) = merchant_metadata {
        let hashmap: HashMap<String, Value> =
            serde_json::from_str(&metadata.peek().to_string()).unwrap_or(HashMap::new());

        for (key, value) in hashmap {
            request_hash_map.insert(format!("external_{key}"), value.to_string());
        }

        meta_data.extend(request_hash_map)
    };
    meta_data
}



