package crypto

type AlgSuite uint16

const (
	AlgRsaAes AlgSuite = 0x0100
	AlgSm2Sm4 AlgSuite = 0x0200
)

func SuiteIdByName(name string) AlgSuite {
	switch name {
	case "rsa", "rsa-aes", "RSA", "1":
		return AlgRsaAes
	case "sm2", "sm2-sm4", "SM2", "2":
		return AlgSm2Sm4
	}

	return 0
}

func SuiteName(id AlgSuite) string {
	switch id {
	case AlgRsaAes:
		return "rsa-aes"
	case AlgSm2Sm4:
		return "sm2-sm4"
	}

	return "unknown"
}

func SuiteProbe(id uint16, candidate AlgSuite) AlgSuite {
	if SuiteName(AlgSuite(id)) == "unknown" {
		return candidate
	}

	return AlgSuite(id)
}

func AllSuites() []AlgSuite {
	return []AlgSuite{AlgRsaAes, AlgSm2Sm4}
}
