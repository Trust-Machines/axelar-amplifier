#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! guarded_string {
    ($Name:ident, $Label:literal, $Regex:expr, $MaxStringLength:expr, $ErrorType:ty, $ErrorVariant:path) => {
        #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $Name(String);
        impl TryFrom<String> for $Name {
            type Error = $ErrorType;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.len() > ($MaxStringLength as usize) {
                    return Err($ErrorVariant($Label, value));
                }
                if $Regex.is_match(&value) {
                    Ok(Self(value))
                } else {
                    Err($ErrorVariant($Label, value))
                }
            }
        }

        impl $Name {
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn len(&self) -> u8 {
                u8::try_from(self.as_str().len()).unwrap()
            }

            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }
        }

        impl Deref for $Name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Borrow<str> for $Name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl Into<String> for $Name {
            fn into(self) -> String {
                self.0
            }
        }

        impl From<&'_ str> for $Name {
            fn from(value: &str) -> Self {
                Self::try_from(value.to_string()).unwrap()
            }
        }

        impl fmt::Display for $Name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

#[macro_export]
macro_rules! define_u8_enum {
    ($(#[$outer:meta])*
     $Name:ident {
         $(
             $(#[$inner:meta])*
             $Variant:ident = $Val:literal),+
     }) =>
    {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[repr(u8)]
        $(#[$outer])*
        pub enum $Name {
            $(  $(#[$inner])*
                $Variant = $Val),*,
        }
        impl $Name {
            /// All members of the enum
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];

            /// Return the u8 representation of the variant
            pub fn to_u8(&self) -> u8 {
                match self {
                    $(
                        $Name::$Variant => $Val,
                    )*
                }
            }

            /// Returns Some and the variant if `v` is a u8 corresponding to a variant in this enum.
            /// Returns None otherwise
            pub fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $(
                        v if v == $Name::$Variant as u8 => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }
        }
    }
}
