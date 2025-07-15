// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package voynicrypto

// AlgorithmType is an enum used to specify which algorithm is being used.
type AlgorithmType string

const (
	None          AlgorithmType = "none"
	Box           AlgorithmType = "box"
	RSASymmetric  AlgorithmType = "rsa-sym"
	RSAAsymmetric AlgorithmType = "rsa-asy"
)

// ParseAlgorithmType takes a string and returns an enum if one matches,
// otherwise returns the None AlgorithmType enum.
func ParseAlgorithmType(algo string) AlgorithmType {
	if algo == string(Box) {
		return Box
	} else if algo == string(RSASymmetric) {
		return RSASymmetric
	} else if algo == string(RSAAsymmetric) {
		return RSAAsymmetric
	}
	return None
}
