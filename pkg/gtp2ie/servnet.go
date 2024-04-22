package gtp2ie

// DecodeServingNet decodes Mobile Country Code (MCC) and Mobile Network Code (MNC)
func DecodeServingNet(data []byte) (MCCMNC, error) {
	return DecodeMCCMNC(data)
}
