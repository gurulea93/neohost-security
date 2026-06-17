module.exports = {
  apps: [
    {
      name: "neohost-security-hub",
      script: "./src/index.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      watch: false,
      max_memory_restart: "512M",
      env: {
        NODE_ENV: "production",
        SERVE_STATIC: "1",
        HOST: "127.0.0.1",
        PORT: "7654"
      }
    }
  ]
};
