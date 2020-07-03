require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-substrate-sign"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-substrate-sign
                   DESC
  s.homepage     = "https://github.com/paritytech/react-native-substrate-sign"
  s.license      = "GPL3"
  s.authors      = { "Admin" => "admin@parity.io" }
  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/paritytech/react-native-substrate-sign.git", :tag => "#{s.version}" }
  s.vendored_libraries = 'ios/libsigner.a'
  s.source_files = "ios/**/*.{h,c,m,swift}"
  s.requires_arc = true

  s.dependency "React"
  # ...
  # s.dependency "..."
end

