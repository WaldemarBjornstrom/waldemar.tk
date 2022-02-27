from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, jsonify
import sesocial, datetime, json
from .models import API
from . import db

api = Blueprint('api', __name__)

def checkapikey(key):
    now = datetime.datetime.now().hour
    apiuser = API.query.filter_by(key=key).first()
    if apiuser:
        rate = json.loads(apiuser.rate)
        if rate['hour'] == str(now):
            if apiuser.tier == 'Free':
                if int(rate['no.']) < 10:
                    rate['no.'] = str(int(rate['no.']) + 1)
                    apiuser.rate = json.dumps(rate)
                    db.session.commit()
                    return True
                else:
                    return "Exceeded rate"
            elif apiuser.tier == 'Paid':
                if int(rate['no.']) < 100:
                    rate['no.'] = str(int(rate['no.']) + 1)
                    apiuser.rate = json.dumps(rate)
                    db.session.commit()
                    return True
                else:
                    return "Exceeded rate"
            else:
                abort(500)
        else:
            rate['hour'] = str(now)
            rate['no.'] = '1'
            apiuser.rate = json.dumps(rate)
            db.session.commit()
            return True
    else:
        return False

@api.route('/sesocial')
def api_sesocial():
    action = str(request.args.get('action'))
    api_key = str(request.args.get('key'))

    if api_key == 'None':
        return "Invalid request type: No api key"

    apikey = checkapikey(api_key)
    if apikey == 'Exceeded rate':
        return "API request rate exceeded"
    elif apikey == False:
        return "Invalid API key"
    
    if action == 'verify':
        try:
            number = str(request.args.get('number'))
        except:
            return "Invalid request type: Unknown"
        if number == 'None':
            return "Invalid request type: Requirements not satisfied"
        if len(number) == 10 or len(number) == 12:
            if number.isdecimal():
                info = {
                    "Valid": sesocial.verify(number),
                    "Gender": sesocial.gender(number)
                }
                return jsonify(info)
            else:
                return "Invalid request type: Not a number"
        else:
            return "Invalid request type: Lenght"
    
    elif action == 'generate':
        try:
            age = str(request.args.get('age'))
            gender = str(request.args.get('gender'))
        except:
            return "Invalid request type: Unknown"

        if gender == 'None' or age == 'None':
            return "Invalid request type: Requirements not satisfied"

        if len(age) > 3:
            return "Invalid request type: Age lenght"
        
        if not age.isdecimal():
            if not age == '-1':
                return "Invalid request type: Age"

        if gender.lower() not in ['male', 'female', 'random']:
            return "Invalid request type: Gender"

        if age == '-1':
            age = 6969
        if gender.lower() == 'random':
            gender = 'none'

        number = sesocial.generate(int(age), gender)
        return str(number)
    else:
        return "No such action: " + action
        
@api.route('/sesocial', methods=['POST'])
def api_sesocial_post():
    action = str(request.form.get('action'))
    api_key = str(request.form.get('key'))
    if not request.environ['HTTP_ORIGIN'] == 'https://waldemar.tk/':
        if api_key == 'None':
            return "Invalid request type: No api key"
    else:
        someinputs = [str(request.form.get('banned1')), str(request.form.get('banned2')), str(request.form.get('banned3')), str(request.form.get('banned4')), str(request.form.get('banned5'))]
        if someinputs[0] == '0326478125' or someinputs[1] == '196383922637' or someinputs[2] == '8411194536' or someinputs[3] == '0263728102' or someinputs[4] == '5527930024':
            api_key = API.query.filter_by(owner='pubapi').first().key
        else:
            return "Stop trying to reverse engineer my code!"

    apikey = checkapikey(api_key)
    if apikey == 'Exceeded rate':
        return "API request rate exceeded"
    elif apikey == False:
        return "Invalid API key"
    
    if action == 'verify':
        try:
            number = str(request.form.get('number'))
        except:
            return "Invalid request type: Unknown"
        if number == 'None':
            return "Invalid request type: Requirements not satisfied"
        if len(number) == 10 or len(number) == 12:
            if number.isdecimal():
                info = {
                    "Valid": sesocial.verify(number),
                    "Gender": sesocial.gender(number)
                }
                return jsonify(info)
            else:
                return "Invalid request type: Not a number"
        else:
            return "Invalid request type: Lenght"
    
    elif action == 'generate':
        try:
            age = str(request.form.get('age'))
            gender = str(request.form.get('gender'))
        except:
            return "Invalid request type: Unknown"

        if gender == 'None' or age == 'None':
            return "Invalid request type: Requirements not satisfied"

        if len(age) > 3:
            return "Invalid request type: Age lenght"
        
        if not age.isdecimal():
            if not age == '-1':
                return "Invalid request type: Age"

        if gender.lower() not in ['male', 'female', 'random']:
            return "Invalid request type: Gender"

        if age == '-1':
            age = 6969
        if gender.lower() == 'random':
            gender = 'none'

        number = sesocial.generate(int(age), gender)
        return str(number)
    else:
        return "No such action: " + action