package gtp2ie

import (
	"gtp2json/config"
	"gtp2json/pkg/gtp2"
	"reflect"
	"testing"
)

func TestProcessIE(t *testing.T) {
	type args struct {
		ie gtp2.IE
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   interface{}
		wantErr bool
	}{
		{
			name: "Test IMSI Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeIMSI, Content: []byte{0x21, 0x43, 0x65}},
			},
			want:    "IMSI",
			want1:   "123456",
			wantErr: false,
		},
		{
			name: "Test MSISDN Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeMSISDN, Content: []byte{0x21, 0x43, 0x65, 0x87}},
			},
			want:    "MSISDN",
			want1:   "12345678",
			wantErr: false,
		},
		{
			name: "Test MEI Decoding",
			args: args{
				ie: gtp2.IE{
					Type:    IETypeMEI,
					Content: []byte{0x68, 0x65, 0x82, 0x50, 0x03, 0x91, 0x48, 0x65},
				},
			},
			want:    "MEI",
			want1:   "8656280530198456",
			wantErr: false,
		},
		{
			name: "Test Unknown IE Type",
			args: args{
				ie: gtp2.IE{Type: 255, Content: []byte{0x01, 0x02}},
			},
			want:    "unknown_type_255",
			want1:   "0102",
			wantErr: false,
		},
		{
			name: "Test FTEID Decoding Error",
			args: args{
				ie: gtp2.IE{Type: IETypeFTEID, Content: []byte{0x00}},
			},
			want:    "F-TEID",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test FTEID Decoding with real data",
			args: args{
				ie: gtp2.IE{
					Type:    IETypeFTEID,
					Content: []byte{0x8a, 0x3f, 0x0f, 0xed, 0x23, 0xd9, 0x94, 0x30, 0xea},
				},
			},
			want: "F-TEID",
			want1: FTEID{
				InterfaceType: uint8(10),
				TEIDGREKey:    "3f0fed23",
				IPv4:          "217.148.48.234",
				IPv6:          "",
			},
			wantErr: false,
		},
		{
			name: "Test ULI Decoding with TAI and ECGI",
			args: args{
				ie: gtp2.IE{
					Type:    IETypeULI,
					Content: []byte{0x18, 0x52, 0xf0, 0x53, 0x17, 0xfd, 0x52, 0xf0, 0x53, 0x03, 0xfd, 0x25, 0x02},
				},
			},
			want: "ULI",
			want1: ULI{
				TAI: &TAI{
					MCCMNC: MCCMNC{
						MCC: "250",
						MNC: "35",
					},
					TAC: "6141",
				},
				ECGI: &ECGI{
					MCCMNC: MCCMNC{
						MCC: "250",
						MNC: "35",
					},
					ECI: "66921730",
				},
			},
			wantErr: false,
		},
		{
			name: "Test ServingNet Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeServingNet, Content: []byte{0x52, 0xf0, 0x53}},
			},
			want:    "ServingNetwork",
			want1:   MCCMNC{MCC: "250", MNC: "35"},
			wantErr: false,
		},
		{
			name: "Test Indication Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeIndication, Content: []byte{0xAA, 0x55}},
			},
			want: "Indication",
			want1: Indication{
				DAF:   true,
				DTF:   false,
				HI:    true,
				DFI:   false,
				OI:    true,
				ISRSI: false,
				ISRAI: true,
				SGWCI: false,
				SQCI:  false,
				UIMSI: true,
				CFSI:  false,
				CRSI:  true,
				PS:    false,
				PT:    true,
				SI:    false,
				MSV:   true,
			},
			wantErr: false,
		},
		{
			name: "Test APN Decoding",
			args: args{
				ie: gtp2.IE{
					Type: IETypeAPN,
					Content: []byte{0x04, 0x69, 0x6e, 0x65, 0x74, 0x03, 0x79, 0x63, 0x63, 0x02, 0x72, 0x75, 0x06, 0x6d, 0x6e, 0x63,
						0x30, 0x33, 0x35, 0x06, 0x6d, 0x63, 0x63, 0x32, 0x35, 0x30, 0x04, 0x67, 0x70, 0x72, 0x73},
				},
			},
			want:    "APN",
			want1:   "inet.ycc.ru.mnc035.mcc250.gprs",
			wantErr: false,
		},
		{
			name: "Test AMBR Decoding with valid data",
			args: args{
				ie: gtp2.IE{Type: IETypeAMBR, Content: []byte{0x00, 0x00, 0x1F, 0x40, 0x00, 0x00, 0x2E, 0xE0}},
			},
			want:    "AMBR",
			want1:   AMBR{Uplink: 8000, Downlink: 12000},
			wantErr: false,
		},
		{
			name: "Test AMBR Decoding with insufficient data",
			args: args{
				ie: gtp2.IE{Type: IETypeAMBR, Content: []byte{0x00, 0x00, 0x1F}}, // Not enough bytes
			},
			want:    "AMBR",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test EBI Valid Low Boundary",
			args: args{
				ie: gtp2.IE{Type: IETypeEBI, Content: []byte{0x06}}, // EBI = 6
			},
			want:    "EBI",
			want1:   EBI(6),
			wantErr: false,
		},
		{
			name: "Test EBI Valid High Boundary",
			args: args{
				ie: gtp2.IE{Type: IETypeEBI, Content: []byte{0x0F}}, // EBI = 15
			},
			want:    "EBI",
			want1:   EBI(15),
			wantErr: false,
		},
		{
			name: "Test EBI Invalid Zero",
			args: args{
				ie: gtp2.IE{Type: IETypeEBI, Content: []byte{0x00}}, // EBI = 0
			},
			want:    "EBI",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test EBI Missing Data",
			args: args{
				ie: gtp2.IE{Type: IETypeEBI, Content: []byte{}}, // No data
			},
			want:    "EBI",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test BearerQoS Decoding",
			args: args{
				ie: gtp2.IE{
					Type: IETypeBearerQoS,
					Content: []byte{
						0x5A,                         // Flags (PCI=1, PL=6, PVI=1)
						0x09,                         // Label (QCI=9)
						0x00, 0x0F, 0xFF, 0xFF, 0xFF, // MBRUL = 268435455
						0x00, 0x0F, 0xFF, 0xFF, 0xFF, // MBRDL = 268435455
						0x00, 0x0A, 0x00, 0x00, 0x00, // GBRUL = 167772160
						0x00, 0x0A, 0x00, 0x00, 0x00, // GBRDL = 167772160
					},
				},
			},
			want: "BearerQoS",
			want1: BearerQoS{
				PCI:   false, // PCI = 1 -> Disabled (False)
				PL:    6,
				PVI:   true, // PVI = 0 -> Enabled (True)
				QCI:   9,
				MBRUL: 268435455,
				MBRDL: 268435455,
				GBRUL: 167772160,
				GBRDL: 167772160,
			},
			wantErr: false,
		},
		{
			name: "Test BearerQoS Decoding with Insufficient Data",
			args: args{
				ie: gtp2.IE{
					Type:    IETypeBearerQoS,
					Content: []byte{0x5A}, // Incomplete data
				},
			},
			want:    "BearerQoS",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test BearerContext Decoding with all fields",
			args: args{
				ie: gtp2.IE{
					Type: IETypeBearerContext,
					Content: []byte{
						0x49, 0x00, 0x01, 0x00, 0x06, // EBI: type 73, length 1, value 6
						0x50, 0x00, 0x16, 0x00, 0x48, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BearerQoS
						0x02, 0x00, 0x02, 0x00, 0x10, 0x00, // Cause: type 2, length 2, value 16 with flags 0x00
						0x57, 0x00, 0x09, 0x00, 0x8a, 0x3f, 0x0f, 0xed, 0x23, 0xd9, 0x94, 0x30, 0xea, // F-TEID
					},
				},
			},
			want: "BearerContext",
			want1: BearerContext{
				EBI: EBI(6),
				BearerQoS: BearerQoS{
					PCI:   false,
					PL:    uint8(2),
					PVI:   true,
					QCI:   uint8(8),
					MBRUL: uint64(0),
					MBRDL: uint64(0),
					GBRUL: uint64(0),
					GBRDL: uint64(0),
				},
				Cause: Cause{
					CauseValue: uint8(16),
					PCE:        false,
					BCE:        false,
					CS:         uint8(0),
				},
				FTEIDs: []FTEID{
					{
						InterfaceType: uint8(10),
						TEIDGREKey:    "3f0fed23",
						IPv4:          "217.148.48.234",
						IPv6:          "",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test Recovery Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeRecovery, Content: []byte{0x05}},
			},
			want:    "Recovery",
			want1:   Recovery(5),
			wantErr: false,
		},
		{
			name: "Test ChargingCharacteristics Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeChargingChars, Content: []byte{0x09, 0x00}},
			},
			want:    "ChargingCharacteristics",
			want1:   ChargingChars{RawValue: "0x0900"},
			wantErr: false,
		},
		{
			name: "Test ChargingCharacteristics Decoding with insufficient data",
			args: args{
				ie: gtp2.IE{Type: IETypeChargingChars, Content: []byte{0x09}},
			},
			want:    "ChargingCharacteristics",
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Test ULITimestamp Decoding",
			args: args{
				ie: gtp2.IE{Type: IETypeULITimestamp, Content: []byte{0xE9, 0x27, 0xD8, 0xD4}},
			},
			want:    "ULITimestamp",
			want1:   "Dec 16, 2023 08:05:40 UTC",
			wantErr: false,
		},
		{
			name: "Test ULITimestamp Decoding with insufficient data",
			args: args{
				ie: gtp2.IE{Type: IETypeULITimestamp, Content: []byte{0x00, 0x00}},
			},
			want:    "ULITimestamp",
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ProcessIE(tt.args.ie)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessIE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ProcessIE() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ProcessIE() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestProcessIE_AllFormats(t *testing.T) {
	type args struct {
		ie     gtp2.IE
		format string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   interface{}
		wantErr bool
	}{
		{
			name: "Test RATType Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypeRATType, Content: []byte{0x06}},
				format: "numeric",
			},
			want:    "RATType",
			want1:   uint8(6),
			wantErr: false,
		},
		{
			name: "Test RATType Text",
			args: args{
				ie:     gtp2.IE{Type: IETypeRATType, Content: []byte{0x06}},
				format: "text",
			},
			want:    "RATType",
			want1:   "EUTRAN",
			wantErr: false,
		},
		{
			name: "Test RATType Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypeRATType, Content: []byte{0x06}},
				format: "mixed",
			},
			want:    "RATType",
			want1:   "EUTRAN (6)",
			wantErr: false,
		},
		{
			name: "Test SelectionMode Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypeSelectionMode, Content: []byte{0x02}},
				format: "numeric",
			},
			want:    "SelectionMode",
			want1:   uint8(2),
			wantErr: false,
		},
		{
			name: "Test SelectionMode Text",
			args: args{
				ie:     gtp2.IE{Type: IETypeSelectionMode, Content: []byte{0x02}},
				format: "text",
			},
			want:    "SelectionMode",
			want1:   "Network provided APN, subscription not verified",
			wantErr: false,
		},
		{
			name: "Test SelectionMode Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypeSelectionMode, Content: []byte{0x02}},
				format: "mixed",
			},
			want:    "SelectionMode",
			want1:   "Network provided APN, subscription not verified (2)",
			wantErr: false,
		},
		{
			name: "Test PDNType Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypePDNType, Content: []byte{0x03}},
				format: "numeric",
			},
			want:    "PDNType",
			want1:   uint8(3),
			wantErr: false,
		},
		{
			name: "Test PDNType Text",
			args: args{
				ie:     gtp2.IE{Type: IETypePDNType, Content: []byte{0x03}},
				format: "text",
			},
			want:    "PDNType",
			want1:   "IPv4v6",
			wantErr: false,
		},
		{
			name: "Test PDNType Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypePDNType, Content: []byte{0x03}},
				format: "mixed",
			},
			want:    "PDNType",
			want1:   "IPv4v6 (3)",
			wantErr: false,
		},
		{
			name: "Test PAA IPv4 Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypePAA, Content: []byte{0x01, 0xC0, 0xA8, 0x01, 0x01}},
				format: "numeric",
			},
			want:    "PAA",
			want1:   PAA{PDNType: uint8(1), IPv4: "192.168.1.1"},
			wantErr: false,
		},
		{
			name: "Test PAA IPv4 Text",
			args: args{
				ie:     gtp2.IE{Type: IETypePAA, Content: []byte{0x01, 0xC0, 0xA8, 0x01, 0x01}},
				format: "text",
			},
			want:    "PAA",
			want1:   PAA{PDNType: "IPv4", IPv4: "192.168.1.1"},
			wantErr: false,
		},
		{
			name: "Test PAA IPv4 Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypePAA, Content: []byte{0x01, 0xC0, 0xA8, 0x01, 0x01}},
				format: "mixed",
			},
			want:    "PAA",
			want1:   PAA{PDNType: "IPv4 (1)", IPv4: "192.168.1.1"},
			wantErr: false,
		},
		{
			name: "Test APN Restriction Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypeAPNRestriction, Content: []byte{0x01}},
				format: "numeric",
			},
			want:    "APNRestriction",
			want1:   uint8(1),
			wantErr: false,
		},
		{
			name: "Test APN Restriction Text",
			args: args{
				ie:     gtp2.IE{Type: IETypeAPNRestriction, Content: []byte{0x01}},
				format: "text",
			},
			want:    "APNRestriction",
			want1:   "Public-1",
			wantErr: false,
		},
		{
			name: "Test APN Restriction Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypeAPNRestriction, Content: []byte{0x01}},
				format: "mixed",
			},
			want:    "APNRestriction",
			want1:   "Public-1 (1)",
			wantErr: false,
		},
		{
			name: "Test Cause Numeric",
			args: args{
				ie: gtp2.IE{Type: IETypeCause, Content: []byte{0x10, 0x06}},
			},
			want:    "Cause",
			want1:   Cause{CauseValue: uint8(16), PCE: true, BCE: true, CS: 0},
			wantErr: false,
		},
		{
			name: "Test Cause Text",
			args: args{
				ie:     gtp2.IE{Type: IETypeCause, Content: []byte{0x10, 0x06}},
				format: "text",
			},
			want: "Cause",
			want1: Cause{
				CauseValue: "Request accepted",
				PCE:        true,
				BCE:        true,
				CS:         0,
			},
			wantErr: false,
		},
		{
			name: "Test Cause Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypeCause, Content: []byte{0x10, 0x06}},
				format: "mixed",
			},
			want: "Cause",
			want1: Cause{
				CauseValue: "Request accepted (16)",
				PCE:        true,
				BCE:        true,
				CS:         0,
			},
			wantErr: false,
		},
		{
			name: "Test UETimeZone Numeric",
			args: args{
				ie:     gtp2.IE{Type: IETypeUETimeZone, Content: []byte{0x10, 0x02}},
				format: "numeric",
			},
			want:    "UETimeZone",
			want1:   UETimeZone{TimeZone: "GMT + 0 hours 15 minutes", DSTAdjustment: uint8(2)},
			wantErr: false,
		},
		{
			name: "Test UETimeZone Text",
			args: args{
				ie:     gtp2.IE{Type: IETypeUETimeZone, Content: []byte{0xA9, 0x01}},
				format: "text",
			},
			want:    "UETimeZone",
			want1:   UETimeZone{TimeZone: "GMT - 3 hours 0 minutes", DSTAdjustment: "+1 hour adjustment for Daylight Saving Time"},
			wantErr: false,
		},
		{
			name: "Test UETimeZone Mixed",
			args: args{
				ie:     gtp2.IE{Type: IETypeUETimeZone, Content: []byte{0x02, 0x00}},
				format: "mixed",
			},
			want:    "UETimeZone",
			want1:   UETimeZone{TimeZone: "GMT + 5 hours 0 minutes", DSTAdjustment: "No adjustment for Daylight Saving Time (0)"},
			wantErr: false,
		},
		{
			name: "Test PCO with P-CSCF IPv4 Address Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x04, 0xC0, 0xA8, 0x00, 0x01,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x000C),
						ProtocolContents: "192.168.0.1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with P-CSCF IPv4 Address Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x04, 0xC0, 0xA8, 0x00, 0x01,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "P-CSCF IPv4 Address",
						ProtocolContents: "192.168.0.1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with P-CSCF IPv4 Address Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x04, 0xC0, 0xA8, 0x00, 0x01,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "P-CSCF IPv4 Address (12)",
						ProtocolContents: "192.168.0.1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with DNS Server IPv4 Address Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x04, 0x08, 0x08, 0x08, 0x08,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x000D),
						ProtocolContents: "8.8.8.8",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with DNS Server IPv4 Address Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x04, 0x08, 0x08, 0x08, 0x08,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "DNS Server IPv4 Address",
						ProtocolContents: "8.8.8.8",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with DNS Server IPv4 Address Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x04, 0x08, 0x08, 0x08, 0x08,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "DNS Server IPv4 Address (13)",
						ProtocolContents: "8.8.8.8",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty P-CSCF IPv4 Address Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x00,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x000C),
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty P-CSCF IPv4 Address Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x00,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "P-CSCF IPv4 Address",
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty P-CSCF IPv4 Address Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0C, 0x00,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "P-CSCF IPv4 Address (12)",
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty DNS Server IPv4 Address Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x00,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x000D),
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty DNS Server IPv4 Address Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x00,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "DNS Server IPv4 Address",
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with Empty DNS Server IPv4 Address Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x0D, 0x00,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "DNS Server IPv4 Address (13)",
						ProtocolContents: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPv4 Link MTU Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x10, 0x02, 0x05, 0xdc, // MTU 1500
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x0010),
						ProtocolContents: uint16(1500),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPv4 Link MTU Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x10, 0x02, 0x05, 0xdc, // MTU 1500
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "IPv4 Link MTU",
						ProtocolContents: uint16(1500),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPv4 Link MTU Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x10, 0x02, 0x05, 0xdc, // MTU 1500
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "IPv4 Link MTU (16)",
						ProtocolContents: uint16(1500),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPCP Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x80, 0x21, 0x0A, 0x03, 0x01, 0x00, 0x0A, 0x81, 0x06, 0xc6, 0x12, 0x40, 0x06, // IPCP with Primary DNS 198.18.64.6
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: uint16(0x8021),
						ProtocolContents: IPCP{
							Code:       3,
							Length:     10,
							Identifier: 1,
							Options: []IPCPOption{
								{
									Type: uint8(0x81),
									Data: "198.18.64.6",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPCP Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x80, 0x21, 0x0A, 0x03, 0x01, 0x00, 0x0A, 0x81, 0x06, 0xc6, 0x12, 0x40, 0x06, // IPCP with Primary DNS 198.18.64.6
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "IPCP",
						ProtocolContents: IPCP{
							Code:       3,
							Length:     10,
							Identifier: 1,
							Options: []IPCPOption{
								{
									Type: "Primary DNS Server IP Address",
									Data: "198.18.64.6",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with IPCP Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x80, 0x21, 0x0A, 0x03, 0x01, 0x00, 0x0A, 0x81, 0x06, 0xc6, 0x12, 0x40, 0x06, // IPCP with Primary DNS 198.18.64.6
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "IPCP (32801)",
						ProtocolContents: IPCP{
							Code:       3,
							Length:     10,
							Identifier: 1,
							Options: []IPCPOption{
								{
									Type: "Primary DNS Server IP Address (129)",
									Data: "198.18.64.6",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with PAP Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc0, 0x23, 0x10, 0x01, 0x00, 0x00, 0x10, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: uint16(0xC023),
						ProtocolContents: PAP{
							Code:       1,
							Identifier: 0,
							Username:   "motiv",
							Password:   "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with PAP Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc0, 0x23, 0x10, 0x01, 0x00, 0x00, 0x10, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "PAP",
						ProtocolContents: PAP{
							Code:       1,
							Identifier: 0,
							Username:   "motiv",
							Password:   "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with PAP Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc0, 0x23, 0x10, 0x01, 0x00, 0x00, 0x10, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76, 0x05, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "PAP (49187)",
						ProtocolContents: PAP{
							Code:       1,
							Identifier: 0,
							Username:   "motiv",
							Password:   "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with SelectedBearerControlMode Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x05, 0x01, 0x02,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       uint16(0x0005),
						ProtocolContents: uint8(2),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with SelectedBearerControlMode Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x05, 0x01, 0x02,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "MS Support of Network Bearer Control indicator",
						ProtocolContents: "MS/NW",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with SelectedBearerControlMode Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0x00, 0x05, 0x01, 0x02,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID:       "MS Support of Network Bearer Control indicator (5)",
						ProtocolContents: "MS/NW (2)",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with CHAP Numeric",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc2, 0x23, 0x1A, 0x02, 0x01, 0x00, 0x1a, 0x10, 0xdd, 0xf0, 0x5f, 0x13, 0x58, 0xd4, 0x17, 0x96, 0x27, 0xb4, 0x45, 0xe2, 0x02, 0xb0, 0xed, 0x23, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "numeric",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: uint16(0xC223),
						ProtocolContents: CHAP{
							Code:       2,
							Identifier: 1,
							Value:      "ddf05f1358d4179627b445e202b0ed23",
							Name:       "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with CHAP Text",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc2, 0x23, 0x1A, 0x02, 0x01, 0x00, 0x1a, 0x10, 0xdd, 0xf0, 0x5f, 0x13, 0x58, 0xd4, 0x17, 0x96, 0x27, 0xb4, 0x45, 0xe2, 0x02, 0xb0, 0xed, 0x23, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "text",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "CHAP",
						ProtocolContents: CHAP{
							Code:       2,
							Identifier: 1,
							Value:      "ddf05f1358d4179627b445e202b0ed23",
							Name:       "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test PCO with CHAP Mixed",
			args: args{
				ie: gtp2.IE{
					Type: IETypePCO,
					Content: []byte{
						0x80, 0xc2, 0x23, 0x1A, 0x02, 0x01, 0x00, 0x1a, 0x10, 0xdd, 0xf0, 0x5f, 0x13, 0x58, 0xd4, 0x17, 0x96, 0x27, 0xb4, 0x45, 0xe2, 0x02, 0xb0, 0xed, 0x23, 0x6d, 0x6f, 0x74, 0x69, 0x76,
					},
				},
				format: "mixed",
			},
			want: "PCO",
			want1: PCO{
				ConfigurationProtocol: 128,
				Options: []PCOOption{
					{
						ProtocolID: "CHAP (49699)",
						ProtocolContents: CHAP{
							Code:       2,
							Identifier: 1,
							Value:      "ddf05f1358d4179627b445e202b0ed23",
							Name:       "motiv",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		config.SetOutputFormat(tt.args.format)
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ProcessIE(tt.args.ie)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessIE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ProcessIE() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ProcessIE() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
