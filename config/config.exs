import Config

if Config.config_env() == :test do
  import_config "test.exs"
end
