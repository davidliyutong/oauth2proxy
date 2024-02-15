import base64
import multiprocessing as mp
import os
import secrets
import sys

import click
from sanic import Sanic
from loguru import logger

from src.config import ServerConfig, OAuth2Config
from src.oidc import bp as oidc_bp, AsyncOauthClient

Sanic.start_method = 'fork'
Sanic.test_mode = True  # attention: this is a hack to make sanic start in fork mode on some linux machines

opt: ServerConfig = ServerConfig()

app = Sanic("root")


def apiserver_check_option(opt: ServerConfig) -> ServerConfig:
    """
    Check and set default values for options
    """
    # Check Token Secret
    if opt.oidc_jwt_secret is None or len(opt.oidc_jwt_secret) == 0:
        logger.warning("Token secret is not set, use random string as token secret")
        opt.oidc_jwt_secret = base64.encodebytes(secrets.token_bytes(32))
    else:
        opt.oidc_jwt_secret = base64.encodebytes(opt.oidc_jwt_secret.encode('utf-8'))

    return opt


def apiserver_prepare_run(opt: ServerConfig) -> Sanic:
    """
    Prepare to run the server
    """
    # set options
    app.ctx.opt = opt
    app.ctx.oauth2_cfg = OAuth2Config.from_server_config(opt)
    app.ctx.oauth2_client = AsyncOauthClient(app.ctx.oauth2_cfg)

    # attach Blueprint to context
    app.blueprint(oidc_bp)
    return app


if __name__ == '__main__':
    global logger

    @click.group()
    @click.pass_context
    def cli(ctx):
        pass


    @cli.command(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
    @click.pass_context
    def init(ctx):
        s = ServerConfig.default_config_string()
        print(s)

    @cli.command(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
    @click.pass_context
    def serve(ctx):
        global opt
        # parse the cli arguments using vyper, then build option from vyper
        opt = ServerConfig.load_config()
        logger.info(f"running option: {opt}")

        # prepare and run the server
        app = apiserver_prepare_run(apiserver_check_option(opt))

        try:
            app.run(host=opt.api_host,
                    port=opt.api_port,
                    access_log=opt.api_access_log,
                    workers=opt.api_num_workers,
                    auto_reload=False,
                    debug=opt.debug)
            logger.debug("debug mode toggled")
        except KeyboardInterrupt as _:
            logger.info("KeyboardInterrupt, terminating workers")
            sys.exit(1)


    cli()
