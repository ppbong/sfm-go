package crypto

import "errors"

var (
	ErrEnvelopeFileSuffix   = errors.New("envelope file suffix unsupported")
	ErrEnvelopeMagic        = errors.New("envelope file magic invalid")
	ErrEnvelopeVersion      = errors.New("envelope version unsupported")
	ErrEnvelopeHeader       = errors.New("envelope header too long")
	ErrEnvelopeHeaderCtx    = errors.New("envelope header format error")
	ErrEnvelopeBodyShort    = errors.New("envelope body too small")
	ErrEnvelopeSignArea     = errors.New("envelope signature area invalid")
	ErrEnvelopeMetaDec      = errors.New("envelope meta area decrypt error")
	ErrEnvelopeChunkLenMiss = errors.New("envelope chunk len prefix missing")
	ErrEnvelopeChunkLen     = errors.New("envelope chunk len error")
	ErrEnvelopeChunkBody    = errors.New("envelope chunk body truncated")
	ErrEnvelopeChunkBodyDec = errors.New("envelope chunk body decrypt error")
	ErrSm4HmacDec           = errors.New("SM4 HMAC mismatch")
)
