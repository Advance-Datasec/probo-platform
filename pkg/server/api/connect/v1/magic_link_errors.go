// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
// OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

package connect_v1

import (
	"context"
	"errors"

	"go.gearno.de/kit/log"
	"go.probo.inc/probo/pkg/iam"
	"go.probo.inc/probo/pkg/server/gqlutils"
)

// magicLinkError maps token failures onto the GraphQL error codes the console
// uses to route to the expired and already-used pages.
//
// This lives outside session_resolvers.go on purpose: gqlgen owns every method
// on *mutationResolver and rewrites them from the schema on each run, so a
// helper method there is silently dropped the next time `go generate` runs
// against a clean checkout.
func magicLinkError(ctx context.Context, logger *log.Logger, err error, logMsg string) error {
	if _, ok := errors.AsType[*iam.ErrExpiredToken](err); ok {
		return gqlutils.TokenExpired(ctx, err)
	}

	if _, ok := errors.AsType[*iam.ErrTokenAlreadyUsed](err); ok {
		return gqlutils.TokenAlreadyUsed(ctx, err)
	}

	if _, ok := errors.AsType[*iam.ErrInvalidToken](err); ok {
		return gqlutils.Invalid(ctx, err)
	}

	// Deliberately reported as an invalid token: telling the caller the address
	// has no active account would leak membership to anyone holding a stale link.
	if _, ok := errors.AsType[*iam.ErrNoActiveAccount](err); ok {
		logger.WarnCtx(ctx, "magic link redeemed without an active profile", log.Error(err))

		return gqlutils.Invalid(ctx, iam.NewInvalidTokenError())
	}

	logger.ErrorCtx(ctx, logMsg, log.Error(err))

	return gqlutils.Internal(ctx)
}
