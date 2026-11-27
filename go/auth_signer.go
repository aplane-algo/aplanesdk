// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// observeAuthSigner reports each signature the key makes during SSH
// authentication. A server can let a client in without asking for a
// signature (x/crypto/ssh tries the "none" method first), so this is how a
// client learns that the server authenticated its key. The wrapper keeps the
// signer's algorithm interfaces, so observing it cannot change which
// signature algorithm is negotiated.
func observeAuthSigner(signer ssh.Signer, signed func()) ssh.Signer {
	basic := &observedSigner{Signer: signer, signed: signed}
	algorithm, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return basic
	}
	wrapped := &observedAlgorithmSigner{observedSigner: basic, algorithm: algorithm}
	if multi, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		return &observedMultiAlgorithmSigner{observedAlgorithmSigner: wrapped, multi: multi}
	}
	return wrapped
}

type observedSigner struct {
	ssh.Signer
	signed func()
}

func (s *observedSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	signature, err := s.Signer.Sign(random, data)
	if err == nil {
		s.signed()
	}
	return signature, err
}

type observedAlgorithmSigner struct {
	*observedSigner
	algorithm ssh.AlgorithmSigner
}

func (s *observedAlgorithmSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signature, err := s.algorithm.SignWithAlgorithm(random, data, algorithm)
	if err == nil {
		s.signed()
	}
	return signature, err
}

type observedMultiAlgorithmSigner struct {
	*observedAlgorithmSigner
	multi ssh.MultiAlgorithmSigner
}

func (s *observedMultiAlgorithmSigner) Algorithms() []string { return s.multi.Algorithms() }
