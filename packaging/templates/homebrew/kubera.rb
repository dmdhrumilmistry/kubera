# Homebrew formula for kubera, rendered by scripts/render-packages.py from
# packaging/templates/homebrew/kubera.rb for each release. Install with:
#   brew install dmdhrumilmistry/tap/kubera
class Kubera < Formula
  desc "Template driven secret detection, verification, analysis and rotation"
  homepage "https://dmdhrumilmistry.github.io/kubera/"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v@VERSION@/kubera-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256:aarch64-apple-darwin@"
    end
    on_intel do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v@VERSION@/kubera-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256:x86_64-apple-darwin@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v@VERSION@/kubera-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256:aarch64-unknown-linux-musl@"
    end
    on_intel do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v@VERSION@/kubera-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256:x86_64-unknown-linux-musl@"
    end
  end

  def install
    bin.install "kubera"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/kubera --version")
    system bin/"kubera", "templates", "test"
  end
end
