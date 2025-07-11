const Config = require("./config")

function PusherConfig(options) {
  Config.call(this, { useTLS: true, ...options })

  if (options.host) {
    this.host = options.host
  } else if (options.cluster) {
    this.host = "api-" + options.cluster + ".pusher.com"
  } else {
    this.host = "mesh.s12g.net"
  }
}

Object.assign(PusherConfig.prototype, Config.prototype)

PusherConfig.prototype.prefixPath = function (subPath) {
  return "/apps/" + this.appId + subPath
}

module.exports = PusherConfig
