# Homebrew formula for kubera, rendered by scripts/render-packages.py from
# packaging/templates/homebrew/kubera.rb for each release. Install with:
#   brew install dmdhrumilmistry/tap/kubera
class Kubera < Formula
  desc "Template driven secret detection, verification, analysis and rotation"
  homepage "https://dmdhrumilmistry.github.io/kubera/"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v0.2.0/kubera-aarch64-apple-darwin.tar.gz"
      sha256 "132fb454bd32862bd91089f222a05fd1fb0cab2a4177fad6048fa92de7184192"
    end
    on_intel do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v0.2.0/kubera-x86_64-apple-darwin.tar.gz"
      sha256 "522bac5c63e340fff9b3717467f54434a11e9554085a91517c711b863c6ce31b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v0.2.0/kubera-aarch64-unknown-linux-musl.tar.gz"
      sha256 "da57373b70553f126fe79c1dd4310b0d04268d107e823120db9878ec1f443176"
    end
    on_intel do
      url "https://github.com/dmdhrumilmistry/kubera/releases/download/v0.2.0/kubera-x86_64-unknown-linux-musl.tar.gz"
      sha256 "cf3d04077b6da3bf70418246799c6e5ecfde3d36634c0786ab2dab037c4526ca"
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
