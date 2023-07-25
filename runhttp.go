package runhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// AutocertConfig holds basic autocert.Manager config.
type AutocertConfig struct {
	Domain   string
	CacheDir string
}

// RunServer runs the provided lightly-configured server (Addr + Handler),
// augmenting it with sane defaults,
// until SIGTERM is received.
func RunServer(ctx context.Context, srv *http.Server, crtCfg *AutocertConfig) error {
	listenAndServe := srv.ListenAndServe

	// set up TLS using autocert
	if crtCfg != nil {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(crtCfg.Domain),
			Cache:      autocert.DirCache(crtCfg.CacheDir),
		}
		srv.TLSConfig = m.TLSConfig()
		listenAndServe = func() error { return srv.ListenAndServeTLS("", "") }
	}

	// listen for signals
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()

	// manage server threads - let them cancel each other
	threads, ctx := errgroup.WithContext(ctx)

	// use the lower-most context for clients - ASAP-closeable
	srv.BaseContext = func(net.Listener) context.Context { return ctx }

	// graceful server shutdown
	threads.Go(func() error {
		defer srv.Close() // force-close the server in the end

		<-ctx.Done() // block till parent ctx is cancelled (signal or listen failure)

		// give it a short while for graceful shutdown - to shake off connections etc
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		return srv.Shutdown(ctx)
	})

	// listen/serve
	threads.Go(listenAndServe)

	// wait for completion (failure or proper signal-triggered shutdown)
	if err := threads.Wait(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
