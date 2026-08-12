package cli

import (
	"fmt"
	"math"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/torkve/bidichan/internal/daemon"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// The knobs a small box needs. The defaults elsewhere are sized for a phone on
// a mobile network, where the bandwidth-delay product is large and the memory
// is somebody else's problem; a controller with a few tens of megabytes wants
// the opposite trade and has to be able to say so.
//
// Registered on listen and connect rather than on the root, so they do not
// appear on the control subcommands where they would mean nothing. Being
// command-local also gets them config-file support for free, since the profile
// merger works on the command's own flag set.
type tuningDef struct {
	memoryLimitMB int
	resumeBuffer  sizeValue
	streamWindow  sizeValue
}

func (d *tuningDef) register(f *pflag.FlagSet) {
	f.IntVar(&d.memoryLimitMB, "memory-limit", 0,
		"soft cap on total memory, in MiB (default: none)")
	f.Var(&d.resumeBuffer, "resume-buffer",
		fmt.Sprintf("per-session send buffer, e.g. 512k (default %s)",
			formatSize(transport.DefaultResumeBuffer)))
	f.Var(&d.streamWindow, "stream-window",
		fmt.Sprintf("per-stream receive window, e.g. 256k (default %s)",
			formatSize(int(peer.DefaultStreamWindow))))
}

// apply validates the values and puts them where they belong. Called after the
// profile has been merged, so a value from a config file is checked the same
// way one typed on the command line is.
func (d *tuningDef) apply(cfg *daemon.Config) error {
	if d.memoryLimitMB < 0 {
		return fmt.Errorf("--memory-limit: %d MiB is not a size", d.memoryLimitMB)
	}
	if d.resumeBuffer != 0 && int(d.resumeBuffer) < transport.MinResumeBuffer {
		return fmt.Errorf("--resume-buffer: %s is below the useful minimum of %s",
			formatSize(int(d.resumeBuffer)), formatSize(transport.MinResumeBuffer))
	}
	if d.streamWindow != 0 && uint32(d.streamWindow) < peer.MinStreamWindow {
		return fmt.Errorf("--stream-window: %s is below the %s the protocol allows",
			formatSize(int(d.streamWindow)), formatSize(int(peer.MinStreamWindow)))
	}
	cfg.ResumeBuffer = int(d.resumeBuffer)
	cfg.StreamWindow = uint32(d.streamWindow)
	// Applied here rather than carried in daemon.Config: this is process-wide
	// runtime state, and a daemon instance has no business owning it. The
	// mobile facade sets its own for the same reason.
	if d.memoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(d.memoryLimitMB) << 20)
	}
	return nil
}

// sizeValue is a byte count written the way people write byte counts: a plain
// number, or one with a k/m/g suffix meaning the binary multiple. Implements
// pflag.Value so the same parser serves the command line and the config file,
// and so a bad value is refused where it was written.
type sizeValue int64

func (v *sizeValue) String() string {
	if v == nil || *v == 0 {
		return ""
	}
	return formatSize(int(*v))
}

func (v *sizeValue) Type() string { return "size" }

func (v *sizeValue) Set(s string) error {
	n, err := parseSize(s)
	if err != nil {
		return err
	}
	*v = sizeValue(n)
	return nil
}

func parseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("%q is not a size", s)
	}
	mult := int64(1)
	switch t[len(t)-1] {
	case 'k', 'K':
		mult, t = 1<<10, t[:len(t)-1]
	case 'm', 'M':
		mult, t = 1<<20, t[:len(t)-1]
	case 'g', 'G':
		mult, t = 1<<30, t[:len(t)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a size (try 512k, 2m, or a plain byte count)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("%q is negative", s)
	}
	// Bounded to what fits an int32, because these end up in an int and a
	// uint32 and the targets this exists for are 32-bit. Unbounded, "5g" would
	// wrap to something small and plausible on armv7 and be accepted — the
	// worst kind of wrong, since nothing would complain.
	if n > math.MaxInt32/mult {
		return 0, fmt.Errorf("%q is larger than this can hold (limit %s)", s, formatSize(math.MaxInt32))
	}
	return n * mult, nil
}

// formatSize writes a size back the way it would have been typed, so an error
// message and a --help default read like the flag they describe.
func formatSize(n int) string {
	switch {
	case n != 0 && n%(1<<30) == 0:
		return strconv.Itoa(n/(1<<30)) + "g"
	case n != 0 && n%(1<<20) == 0:
		return strconv.Itoa(n/(1<<20)) + "m"
	case n != 0 && n%(1<<10) == 0:
		return strconv.Itoa(n/(1<<10)) + "k"
	default:
		return strconv.Itoa(n)
	}
}
