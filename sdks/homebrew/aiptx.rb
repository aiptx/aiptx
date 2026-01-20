# Homebrew Formula for AIPTX
# AI-Powered Penetration Testing Framework
#
# To install:
#   brew tap aiptx/tap
#   brew install aiptx
#
# Or directly:
#   brew install aiptx/tap/aiptx

class Aiptx < Formula
  include Language::Python::Virtualenv

  desc "AI-Powered Penetration Testing Framework"
  homepage "https://aiptx.io"
  url "https://files.pythonhosted.org/packages/source/a/aiptx/aiptx-2.0.6.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/aiptx/aiptx.git", branch: "main"

  depends_on "python@3.11"
  depends_on "nmap"

  # Optional dependencies for full installation
  option "with-full", "Install with all optional dependencies"

  def install
    virtualenv_install_with_resources

    # Create wrapper scripts
    (bin/"aiptx").write_env_script(
      libexec/"bin/aiptx",
      PATH: "#{libexec}/bin:$PATH"
    )
  end

  def caveats
    <<~EOS
      AIPTX has been installed!

      To get started:
        1. Run the setup wizard:
           $ aiptx setup

        2. Check status:
           $ aiptx status

        3. Run your first scan:
           $ aiptx scan example.com

      For AI-powered scanning, you'll need an API key from:
        - Anthropic (Claude): https://console.anthropic.com
        - OpenAI (GPT-4): https://platform.openai.com

      Documentation: https://aiptx.io/docs
    EOS
  end

  test do
    assert_match "AIPTX v", shell_output("#{bin}/aiptx --version")
  end
end
