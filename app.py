from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, IntegerField, FileField, SelectField, FormField, RadioField, FieldList, SelectMultipleField
from wtforms.validators import DataRequired, IPAddress, Optional, InputRequired, Length, ValidationError
from flask_wtf.file import FileAllowed
from pprint import pprint
from flask_wtf.csrf import CSRFError
from jinja2 import Template
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename
import os
import ipaddress
import csv
import subprocess

app = Flask(__name__)

# Flask-WTF requires an encryption key - the string can be anything
app.config['SECRET_KEY'] = 'C2HWGVoMGfNTBsrYQg8EcMrdTimkZfAb'

# Flask-Bootstrap requires this line
Bootstrap(app)

##custom validator for netmask
def validate_netmask(self,input):
    list_of_netmasks = ['255.255.255.252','255.255.255.248','255.255.255.240','255.255.255.224','255.255.255.192','255.255.255.128','255.255.255.0','255.255.254.0','255.255.252.0','255.255.248.0','255.255.240.0','255.255.224.0','255.255.192.0','255.255.128.0','255.255.0.0','255.254.0.0','255.252.0.0','255.248.0.0','255.240.0.0','255.224.0.0','255.192.0.0','255.128.0.0','255.0.0.0','254.0.0.0','252.0.0.0','248.0.0.0','240.0.0.0','224.0.0.0','192.0.0.0','128.0.0.0']
    if input.data not in list_of_netmasks:
        raise ValidationError("This is not a valid Netmask")

##custom validator for bgp asn
def validate_asn(self,input):

    if int(input.data) == 56278 or int(input.data) > 65535 or int(input.data) < 0:
        raise ValidationError("This is not a valid BGP ASN Input")

#custom validator for vlans
def validate_vlan(input):
    vlan_parsed = []
    for i in input:
        try:
            vlan_dict = {}
            i = i.strip()
            id = i.split(':')[0]
            if int(id) <= 0:
                raise ValidationError("Vlan input id {} should be greater than 0. Please check".format(id))
            vlan_ip = i.split(":")[1]
            if not ipaddress.ip_interface(vlan_ip):
                raise ValidationError("Vlan input IP {} is invalid. Please check".format(vlan_ip))
            vlan_dict["id"] = id
            vlan_dict["ipv4-address"] = vlan_ip.split("/")[0]
            vlan_dict["subnet-mask"] = vlan_ip.split("/")[1]
            vlan_parsed.append(vlan_dict)
        except:
            raise ValidationError("Vlan input {} is invalid. Please check".format(i))
    return(vlan_parsed)

#function to validate string input
def validate_string(self,input):
    x = input.data
    if x.isdigit():
        raise ValidationError("This is not a valid Input")



#function to create bootstrap user data
def create_bootstrap():
    with open('outputs/bootstrap_userdata.txt','w+') as boot_cfg:
        boot_cfg.write("#!/bin/bash")
        command_list = []
        with open('outputs/temp.txt','r') as f:
            for line in f.readlines():
                if line != "\n" and line != "":
                    command_list.append(line.strip())
        boot_cfg.write("\n")
        for line in command_list:
            boot_cfg.write("clish -c '{}'".format(line))
            boot_cfg.write("\n")

        pprint(command_list)


##base flask form model
class BaseForm(FlaskForm):
    site = StringField('Site Name*', validators=[DataRequired(message="Site name is mandatory"), InputRequired(message="Site name is mandatory"), Length(min=3, max=10,message="Site name is mandatory"), validate_string],description="Enter your Site Name")
    mdsm = StringField('MDSM Server IP*', validators=[IPAddress(message="MDSM IP is Invalid")])
    mdsm_logserver = StringField('MDSM LogServer IP', validators=[IPAddress(message="MDSM Log Server IP is Invalid"), Optional()], description="This is Optional")
    sic = StringField('SIC Key*', validators=[DataRequired(),Length(min=3,max=10)])
    dns1 = StringField('DNS1', validators=[Optional(),IPAddress(message="DNS1 IP is invalid")],default="8.8.8.8",description="Default to use 8.8.8.8")
    dns2 = StringField('DNS2', validators=[Optional(), IPAddress(message="DNS2 IP is invalid")],default="4.2.2.2",description="Default to use 4.2.2.2")
    setup = RadioField('Label*',validators=[InputRequired(message="Please select either Standalone or HA")],choices=['Standalone','HA'],description="Select HA or Standalone")
    isp_type = RadioField('Label*',validators=[InputRequired(message="Please select either Single ISP or Dual ISP")],choices=['Single ISP','Dual ISP'], description="Select Single ISP or Dual ISP")
    config_type = SelectField('Config Type*', choices=['Primary','Secondary'], validators=[DataRequired()], description="Ignore if your site has Standalone FW")
    lan1_ip = StringField('LAN1 IP*', validators=[DataRequired(message="LAN1 IP is mandatory"), IPAddress(message="LAN1 IP is Invalid")])
    lan1_mask = StringField('LAN1 Mask*', validators=[DataRequired(message="LAN1 mask is mandatory"), validate_netmask])
    lan1_gateway = StringField('LAN1 Gateway*', validators=[IPAddress(message="LAN1 Gateway IP is Invalid"), Optional()],description="Optional if FW is default lan gw")
    lan2_ip = StringField('LAN2 IP*', validators=[DataRequired(message="LAN2 IP is mandatory"),IPAddress(message="LAN2 IP is Invalid")])
    lan2_mask = StringField('LAN2 Mask*', validators=[DataRequired(message="LAN2 mask is mandatory"), validate_netmask])
    lan2_gateway = StringField('LAN2 Gateway*', validators=[DataRequired(message="LAN2 Gateway is mandatory"), IPAddress(message="LAN2 Gateway IP is Invalid")])
    lan3_ip = StringField('LAN3 IP', validators=[IPAddress(message="LAN3 IP is Invalid"),Optional()], description="Leave this with default if your site has HA", default="169.254.10.1")
    lan3_mask = StringField('LAN3 Mask', validators=[validate_netmask,Optional()], description="Leave this with default if your site has HA", default="255.255.255.248")
    lan3_gateway = StringField('LAN3 Gateway', validators=[IPAddress(message="LAN3 Gateway IP is Invalid"),Optional()], description="Leave this with default if your site has HA", default="169.254.10.3")
    lan4_ip = StringField('LAN4 IP', validators=[IPAddress(message="LAN4 IP is Invalid"),Optional()], description="Leave this with default if your site has HA", default="169.254.11.1")
    lan4_mask = StringField('LAN4 Mask', validators=[validate_netmask,Optional()], description="Leave this with default if your site has HA", default="255.255.255.248")
    lan4_gateway = StringField('LAN4 Gateway', validators=[IPAddress(message="LAN4 Gateway IP is Invalid"),Optional()], description="Leave this with default if your site has HA", default="169.254.11.3")
    bgp_asn = IntegerField('Local BGP ASN*', validators=[Optional(),validate_asn])
    bgp_lan_asn = IntegerField('Peer BGP ASN(LAN)', validators=[Optional(),validate_asn], description="This is Optional")
    bgp_lan_peer = StringField('BGP Peer IP(LAN) ', validators=[IPAddress(message="BGP LAN Peer IP is Invalid"), Optional()], description="This is Optional")
    redis_bgp = BooleanField("Redistribute BGP", validators=[Optional()], default=False)
    redis_static = BooleanField("Redistribute Static", validators=[Optional()], default=False)
    redis_ospf = BooleanField("Redistribute OSPF", validators=[Optional()], default=False)
    mgmt_ip = StringField('Mgmt IP', validators=[IPAddress(message="Mgmt IP is Invalid"),Optional()])
    mgmt_mask = StringField('Mgmt Mask', validators=[validate_netmask,Optional()])
    mgmt_gateway = StringField('Mgmt Gateway', validators=[IPAddress(message="Mgmt Gateway IP is Invalid"),Optional()])
    routes_file = FileField("Upload csv file for Lan routes", validators=[Optional(),FileAllowed(['csv'],'Upload .csv file Only!')], description="This is Optional")
    snmp_user = StringField('SNMPv3 User*', validators=[DataRequired(),Length(min=3,max=15),validate_string])
    snmp_community = StringField('SNMP Community*', validators=[DataRequired(),Length(min=3,max=20),validate_string])
    snmp_auth_pass = StringField('SNMP Auth-Pass*', validators=[DataRequired(),Length(min=3,max=20),validate_string])
    snmp_priv_pass = StringField('SNMP Priv-Pass*', validators=[DataRequired(),Length(min=3,max=20),validate_string])
    submit = SubmitField('Submit')






@app.route('/', methods=['GET', 'POST'])
def index():
    file_loader = FileSystemLoader('jinja2')
    env = Environment(loader=file_loader)
    form = BaseForm()
    message = ""
    data = {}
    if form.validate_on_submit() and request.method == 'POST':
        data['site'] = form.site.data.strip()
        data['mdsm'] = form.mdsm.data
        data['mdsm_logserver'] = form.mdsm_logserver.data
        data['sic'] = form.sic.data.strip()
        data['dns1'] = form.dns1.data
        data['dns2'] =  form.dns2.data
        data['setup'] = form.setup.data
        data['isp_type'] = form.isp_type.data
        data['config_type'] = form.config_type.data
        interfaces =  {}
        interfaces['name'] = "LAN1"
        interfaces['ipv4-address'] = form.lan1_ip.data
        interfaces['subnet-mask'] = form.lan1_mask.data
        interfaces['gateway'] = form.lan1_gateway.data
        data['interfaces'] = []
        data['interfaces'].append(interfaces)
        interfaces = {}
        interfaces['name'] = "LAN2"
        interfaces['ipv4-address'] = form.lan2_ip.data
        interfaces['subnet-mask'] = form.lan2_mask.data
        interfaces['gateway'] = form.lan2_gateway.data
        data['interfaces'].append(interfaces)
        wan = {}
        data['wan'] = []
        if form.setup.data == 'HA':
            if form.isp_type.data == 'Dual ISP':
                if form.config_type.data == 'Primary':
                    wan['name'] = "LAN3"
                    wan['ipv4-address'] = "169.254.10.1"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.10.3"
                    data['wan'].append(wan)
                    wan = {}
                    wan['name'] = "LAN4"
                    wan['ipv4-address'] = "169.254.11.1"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.11.3"
                    data['wan'].append(wan)
                else:
                    wan['name'] = "LAN3"
                    wan['ipv4-address'] = "169.254.10.2"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.10.3"
                    data['wan'].append(wan)
                    wan = {}
                    wan['name'] = "LAN4"
                    wan['ipv4-address'] = "169.254.11.2"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.11.3"
                    data['wan'].append(wan)
            else:
                if form.config_type.data == 'Primary':
                    wan['name'] = "LAN3"
                    wan['ipv4-address'] = "169.254.10.1"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.10.3"
                    data['wan'].append(wan)
                else:
                    wan['name'] = "LAN3"
                    wan['ipv4-address'] = "169.254.10.2"
                    wan['subnet-mask'] = "255.255.255.248"
                    wan['gateway'] = "169.254.10.3"
                    data['wan'].append(wan)
        else:
            if form.isp_type.data == 'Dual ISP':
                wan['name'] = "LAN3"
                wan['ipv4-address'] = form.lan3_ip.data
                wan['subnet-mask'] = form.lan3_mask.data
                wan['gateway'] = form.lan3_gateway.data
                data['wan'].append(wan)
                wan = {}
                wan['name'] = "LAN4"
                wan['ipv4-address'] = form.lan4_ip.data
                wan['subnet-mask'] = form.lan4_mask.data
                wan['gateway'] = form.lan4_gateway.data
                data['wan'].append(wan)
            else:
                wan['name'] = "LAN3"
                wan['ipv4-address'] = form.lan3_ip.data
                wan['subnet-mask'] = form.lan3_mask.data
                wan['gateway'] = form.lan3_gateway.data
                data['wan'].append(wan)


        if form.setup.data == 'HA':
            ha = {}
            data['ha'] = []
            if form.config_type.data == 'Primary':
                ha['name'] = "LAN10"
                ha['ipv4-address'] = "169.254.9.1"
                ha['subnet-mask'] = "255.255.255.252"
                data['ha'].append(ha)
            else:
                ha['name'] = "LAN10"
                ha['ipv4-address'] = "169.254.9.2"
                ha['subnet-mask'] = "255.255.255.252"
                data['ha'].append(ha)

        #snmp
        snmp_dict = {}
        snmp_dict['snmp_user'] = form.snmp_user.data.strip()
        snmp_dict['snmp_community'] = form.snmp_community.data.strip()
        snmp_dict['snmp_auth_pass'] = form.snmp_auth_pass.data.strip()
        snmp_dict['snmp_priv_pass'] = form.snmp_priv_pass.data.strip()
        data['snmp'] = snmp_dict

        template = env.get_template('system.j2')
        system_out = template.render(data=data,lan2_gateway=form.lan2_gateway.data)
        with open("outputs/temp.txt", "w+") as f:
            for line in system_out:
                f.write(line)


        vlan_list = request.form.getlist('field[]')
        if len(vlan_list) > 0 and vlan_list[0] != '':
            print("Found vlan")
            x = validate_vlan(vlan_list)
            data['vlan'] = x
            pprint(x)
        else:
            print("No vlan info found. Skipping....")



        #mgmt section
        data['mgmt'] = []
        mgmt_dict = {}
        mgmt_dict['name'] = "Mgmt"
        mgmt_dict['ipv4-address'] = form.mgmt_ip.data
        mgmt_dict['subnet-mask'] = form.mgmt_mask.data
        mgmt_dict['gateway'] = form.mgmt_gateway.data
        data['mgmt'].append(mgmt_dict)


        template = env.get_template('interfaces.j2')
        intf_out = template.render(data=data)
        with open("outputs/temp.txt", "a+") as f:
            for line in intf_out:
                f.write(line)

        #routes
        f = form.routes_file.data
        routes_list = []
        if f:
            filename = secure_filename(f.filename)
            f.save(os.path.join('uploads', filename))
            with open(os.path.join('uploads', filename), 'r', encoding='utf-8-sig') as csvfile:
                datareader = csv.reader(csvfile)

                for row in datareader:
                    if ipaddress.ip_network(row[0]):
                        routes_list.append(row[0])
                    else:
                        raise ValidationError("Invalid destination in uploaded file")
        print(routes_list)
        data['lan_routes'] = routes_list
        if len(routes_list) > 0:
            if not form.lan1_gateway.data:
                raise ValidationError("LAN1 Gateway is mandatory for generating route config")
            else:
                template = env.get_template('routes.j2')
                routes_out = template.render(data=data, lan1_gateway=form.lan1_gateway.data)
                with open("outputs/temp.txt", "a+") as f:
                    for line in routes_out:
                        f.write(line)

        #bgp
        if (form.bgp_asn.data):
            if int(form.bgp_asn.data) != 56278 and int(form.bgp_asn.data) < 65535 and int(
                    form.bgp_asn.data) > 0:
                data['bgp_asn'] = form.bgp_asn.data
                data['redis_bgp'] = form.redis_bgp.data
                data['redis_static'] = form.redis_static.data
                data['redis_ospf'] = form.redis_ospf.data
                data['bgp_lan'] = []
                if form.bgp_lan_asn.data != "" and form.bgp_lan_peer.data != "":
                    bgp_lan = {}
                    bgp_lan['peer_asn'] = form.bgp_lan_asn.data
                    bgp_lan['peer_ip'] = form.bgp_lan_peer.data
                    data['bgp_lan'].append(bgp_lan)
                if form.lan2_gateway.data:
                    template = env.get_template('bgp.j2')
                    bgp_out = template.render(bgp_asn=form.bgp_asn.data, lan2_gateway=form.lan2_gateway.data,
                                              data=data)
                    with open("outputs/temp.txt", "a+") as f:
                        f.write(bgp_out)
                #                    print(bgp_out)
                else:
                    raise ValidationError("LAN2 gateway is required for generating BGP config")

        pprint(data)
        #function to create bootstrap
        create_bootstrap()
        run_cmd = os.system('mkisofs -output outputs/configdrive.iso -volid cidata -joliet -V config-2 -rock outputs/bootstrap_userdata.txt')
        return redirect(url_for('success'))
    else:
        print("else loop")
        print("Validation Failed")
        print(form.errors)
    return render_template('index1.html', form=form, message=message)

@app.route('/success', methods =['GET', 'POST'])
def success():
    return render_template('success.html')

@app.route('/download')
def download_file():
    return send_file('/Users/rishabh.parihar/Documents/NetDevOpsToolkit/flask/outputs/temp.txt',
                     attachment_filename='commands.txt',as_attachment=True,mimetype='text')

@app.route('/download_bootstrap')
def download_bootstrap():
    return send_file('/Users/rishabh.parihar/Documents/NetDevOpsToolkit/flask/outputs/configdrive.iso',
                     attachment_filename='configdrive.iso',as_attachment=True,mimetype='iso')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)