//! Module containing concept of an Ethereum RPC method.

use serde::{de::DeserializeOwned, Serialize};

/// A trait defining an Ethereum RPC method.
pub trait Method {
    type Params;
    type ParamsAs: Serialize + From<Self::Params>;
    type Result;
    type ResultAs: DeserializeOwned + Into<Self::Result>;

    fn name() -> &'static str;
}

#[macro_export]
macro_rules! method {
    (
        $(#[$attr:meta])*
        $pub:vis struct $type:ident as $name:literal
            $params:ty $([$paramsas:ty])? => $result:ty $([$resultas:ty])?;
    ) => {
        $(#[$attr])*
        $pub struct $type;

        impl $crate::method::Method for $type {
            type Params = $params;
            type ParamsAs = $crate::_opt!({$($paramsas)*} : {$params});
            type Result = $result;
            type ResultAs = $crate::_opt!({$($resultas)*} : {$result});

            fn name() -> &'static str {
                $name
            }
        }
    };
}

#[macro_export]
macro_rules! module {
    (
        $(#[$attr:meta])*
        $pub:vis mod $mod:ident {
            $(
                $(#[$ma:meta])*
                $mv:vis struct $mt:ident as $mn:literal
                    $mp:ty $([$mpp:ty])? => $mr:ty $([$mrr:ty])?;
            )*
        }
    ) => {
        $(#[$attr])*
        $pub mod $mod {
            use $crate::types::*;

            $(
                $crate::method! {
                    $(#[$ma])* $mv struct $mt as $mn
                        $mp $([$mpp])* => $mr $([$mrr])*;
                }
            )*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! _opt {
    ({} : { $($default:tt)* }) => {
        $($default)*
    };
    ({ $($override:tt)+ } : { $($default:tt)* }) => {
        $($override)*
    };
}
