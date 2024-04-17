package gtp2ie

import (
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
				ie: gtp2.IE{Type: 99, Content: []byte{0x01, 0x02}},
			},
			want:    "unknown_type_99",
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
				InterfaceType: "10",
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
