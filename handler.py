
# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import hmac
import hashlib
import time
import logging
import json
import boto3
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(
    level=logging.INFO,
    format=f'%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.debug('The script is starting.')
logger.info('Connecting to SlackApp...')
ssmclient=boto3.client('ssm')
# process_before_response must be True when running on FaaS
sign_secret = ssmclient.get_parameter(Name='PRBSlackSigningSecret', WithDecryption=True)['Parameter']['Value']
app = App(process_before_response=True,
          token=ssmclient.get_parameter(Name='PRBSlackBotToken', WithDecryption=True)['Parameter']['Value'],
          signing_secret=ssmclient.get_parameter(Name='PRBSlackSigningSecret', WithDecryption=True)['Parameter']['Value']
          )
logger.info(app)

@app.event("app_home_opened")
def update_home_tab(client, event, logger):
    print("start your home app")
    try:
        # views.publish is the method that your app uses to push a view to the Home tab

        client.views_publish(
                # the user that opened your app's app home
                user_id=event["user"],
                # the view object that appears in the app home
                view={
                    "type": "home",
                    "blocks": [
                        {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Welcome AWS V8 Cloudservices Admin! I am the self-server *Password-Reset-Bot* and I am here to assist you with your access to the Active Directory in each region. To get started you will need to know the AWS Region and for the region I will be assisting you with.\n\n *Are you ready to get started?*"
                            }
                        },
                    {
                        "type": "divider"
                        },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Reset Password!",
                                    "emoji": True
                                    },
                                "style": "primary",
                                "value": "click_me_123",
                                "action_id": "actionId-0",
                                }
                            ]
                            }
                    ]
                }
        )

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")
        logger.info(event)


@app.action("actionId-0")
def handle_some_action(ack, body, logger, client):
    ack()
    client.views_open(
            # Pass a valid trigger_id within 3 seconds of receiving it
            trigger_id=body["trigger_id"],
            # View payload
            view={
                "type": "modal",
                "callback_id": "view_1",
                "title": {
                    "type": "plain_text",
                    "text": "Password Reset Bot",
                    "emoji": True
                    },
                "submit": {
                    "type": "plain_text",
                    "text": "Submit",
                    "emoji": True
                    },
                "close": {
                    "type": "plain_text",
                    "text": "Cancel",
                    "emoji": True
                    },
                "blocks": [
                    {
                        "type": "section",
                        "block_id": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Please fill this form to reset your password",
                            "emoji": True
                            }
                        },
                    {
                        "type": "divider"
                        },
                    {
                        "type": "input",
                        "block_id": "userBlock",
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "user"
                            },
                        "label": {
                            "type": "plain_text",
                            "text": "Please provide your Username",
                            "emoji": True
                            }
                        },
                    {
                        "type": "input",
                        "block_id": "RegionBlock",
                        "element": {
                            "type": "static_select",
                            "placeholder": {
                                "type": "plain_text",
                                "text": "Select an item",
                                "emoji": True
                                },
                            "options": [
                                {
                                    "text": {
                                        "type": "plain_text",
                                        "text": "us-east-1",
                                        "emoji": True
                                        },
                                    "value": "value-0"
                                    },
                                {
                                    "text": {
                                        "type": "plain_text",
                                        "text": "us-east-2",
                                        "emoji": True
                                        },
                                    "value": "value-1"
                                    },
                                {
                                    "text": {
                                        "type": "plain_text",
                                        "text": "us-west-2",
                                        "emoji": True
                                        },
                                    "value": "value-2"
                                    }
                                ],
                            "action_id": "selectRegion"
                            },
                        "label": {
                            "type": "plain_text",
                            "text": "Please select your Region",
                            "emoji": True
                            }
                        },
                    {
                            "type": "input",
                            "block_id": "PasswordBlock",
                            "element": {
                                "type": "plain_text_input",
                                "action_id": "password"
                                },
                            "label": {
                                "type": "plain_text",
                                "text": "Please Enter your new Password",
                                "emoji": True
                                }
                            },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "plain_text",
                                "text": "Note: your password must include any of three categories i.e lowercase, numbers, special character and Uppercase. your password *must not include your username* and it must be *16 characters*",
                                "emoji": True
                            }
                        ]
                    }
                    ]
                }
            )
    logger.info(body)

@app.view("view_1")
def handle_submission(ack, client, body, view, logger):
    user = body["user"]["id"]
    username = view["state"]["values"]["userBlock"]
    region = view["state"]["values"]["RegionBlock"]["selectRegion"]["selected_option"]["text"]["text"]
    password = view["state"]["values"]["PasswordBlock"]["password"]["value"]
    # Acknowledge the view_submission request and close the modal
    ack()
    # Message to send user
    msg = ""
    try:
        # Save to DB
        msg = username["user"]["value"]+f", your submission is successful to reset your password in region "+region
        message ={"username": username["user"]["value"],
                  "password": password,
                  "channel": user}
        snsclient = boto3.client('sns', region_name=region)
        response = snsclient.publish(
                TargetArn="arn:aws:sns:"+region+":"+handler.aws_account_id+":PasswordResetBot-"+region,
                Message=json.dumps({'default': json.dumps(message)}),
                MessageStructure='json'
                )
        client.chat_postMessage(channel=user, text=msg)
    except Exception as e:
        # Handle error
        msg = "There was an error with your submission"
        client.chat_postMessage(channel=user, text=msg)
        
@app.event("message")
def handle_message_events(body, logger):
    logger.info(body)

SlackRequestHandler.clear_all_log_handlers()
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)


def handler(event, context):
    print(event)
    handler.aws_account_id = context.invoked_function_arn.split(":")[4]
    print("Account ID:"+handler.aws_account_id)
    logger.info(event)
    timestamp = event['headers']['X-Slack-Request-Timestamp']
    request_body = event['body']
    if abs(time.time() - int(timestamp)) > 60 * 5:
    # The request timestamp is more than five minutes from local time.
    # It could be a replay attack, so let's ignore it.
       return
    sig_basestring = 'v0:' + timestamp + ':' + request_body
    my_signature = 'v0=' + hmac.new(sign_secret.encode(), sig_basestring.encode(), hashlib.sha256).hexdigest()
    slack_signature = event['headers']['X-Slack-Signature']
    if hmac.compare_digest(my_signature, slack_signature):
        print("signing secret verified")
        slack_handler = SlackRequestHandler(app=app)
        #SocketModeHandler(app, ssmclient.get_parameter(Name='PRBSlackAppToken', WithDecryption=True)['Parameter']['Value']).start()
        return slack_handler.handle(event, context)