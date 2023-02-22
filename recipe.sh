#!/bin/bash

#title                  recipe.sh
#description            CAFe IDP installation recipe for RPILOT
#author                 Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor       Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date                   2023/02/21
#version                0.0.2
#
#changelog              1.0.0 - 2023/02/XX - Initial version for Ubuntu 22.04 and Shibboleth IDP 4.3.0.

RET=""
DEBUG="1"
F_LOG="/root/cafe-recipe.log"
REPOSITORY="https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main"
SRCDIR="/root/shibboleth-identity-provider-4.3.0"
SHIBDIR="/opt/shibboleth-idp"

function setProperty {
	#Based on: https://gist.github.com/kongchen/6748525
	awk -v pat="^$1 ?=" -v value="$1 = $2" '{ if ($0 ~ pat) print value; else print $0; }' $3 > $3.tmp
	mv $3.tmp $3
}

#
# DEBUG
#

if [ ${DEBUG} -eq 1 ] ; then
    echo "### INFORMACOES DE DEBUG ###" | tee -a ${F_LOG}
    echo "`date`" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    echo "Variáveis:" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    echo "DIRETORIO                 = ${DIRETORIO}" | tee -a ${F_LOG}
    echo "LDAPADDOMAIN              = ${LDAPADDOMAIN}" | tee -a ${F_LOG}
    echo "LDAPSERVER                = ${LDAPSERVER}" | tee -a ${F_LOG}
    echo "LDAPSERVERPORT            = ${LDAPSERVERPORT}" | tee -a ${F_LOG}
    echo "LDAPSERVERSSL             = ${LDAPSERVERSSL}" | tee -a ${F_LOG} 
    echo "LDAPSERVERSSLUSE          = ${LDAPSERVERSSLUSE}" | tee -a ${F_LOG}
    echo "LDAPSERVERPROTO           = ${LDAPSERVERPROTO}" | tee -a ${F_LOG}
    echo "LDAPDN                    = ${LDAPDN}" | tee -a ${F_LOG}
    echo "LDAPUSER                  = ${LDAPUSER}" | tee -a ${F_LOG}
    echo "LDAPPWD                   = ${LDAPPWD}" | tee -a ${F_LOG}
    echo "CONTACT                   = ${CONTACT}" | tee -a ${F_LOG}
    echo "CONTACTMAIL               = ${CONTACTMAIL}" | tee -a ${F_LOG}
    echo "ORGANIZATION              = ${ORGANIZATION}" | tee -a ${F_LOG}
    echo "INITIALS                  = ${INITIALS}" | tee -a ${F_LOG}
    echo "URL                       = ${URL}" | tee -a ${F_LOG}
    echo "DOMAIN                    = ${DOMAIN}" | tee -a ${F_LOG}
    echo "OU                        = ${OU}" | tee -a ${F_LOG}
    echo "CITY                      = ${CITY}" | tee -a ${F_LOG}
    echo "UF                        = ${UF}" | tee -a ${F_LOG}
    echo "UFUPPER                   = ${UFUPPER}" | tee -a ${F_LOG}
    echo "STATE                     = ${STATE}" | tee -a ${F_LOG}
    echo "POLLER                    = ${POLLER}" | tee -a ${F_LOG}
    echo "MSG_AUTENTICACAO          = ${MSG_AUTENTICACAO}" | tee -a ${F_LOG}
    echo "MSG_URL_RECUPERACAO_SENHA = ${MSG_URL_RECUPERACAO_SENHA}" | tee -a ${F_LOG}            
    echo "COMPUTEDIDSALT            = ${COMPUTEDIDSALT}" | tee -a ${F_LOG}
    echo "PERSISTENTDIDSALT         = ${PERSISTENTDIDSALT}" | tee -a ${F_LOG}
    echo "FTICKSSALT                = ${FTICKSSALT}" | tee -a ${F_LOG}
fi

#
# Atualizacao de pacotes e distribuicao
#

echo "" | tee -a ${F_LOG} 
echo "Atualizando pacotes e distribuicao" | tee -a ${F_LOG}

apt update && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt remove --purge -y vim-tiny  && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt dist-upgrade -y && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt install -y less vim bzip2 unzip ssh dialog ldap-utils build-essential net-tools  && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# Configuracao do logrotate
#

echo "" | tee -a ${F_LOG} 
echo "Configurando logrotate" | tee -a ${F_LOG}

cat > /etc/logrotate.conf <<-EOF
# see "man logrotate" for details
# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
compress
nodelaycompress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
EOF

#
# Configuracao do firewall
#

echo "" | tee -a ${F_LOG} 
echo "Configurando firewall" | tee -a ${F_LOG}

mkdir -p /opt/rnp/firewall/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/firewall/firewall.rules -O /etc/default/firewall && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/firewall/firewall.service -O /etc/systemd/system/firewall.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/firewall/firewall.sh -O /opt/rnp/firewall/firewall.sh && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

chmod 755 /opt/rnp/firewall/firewall.sh && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chmod 664 /etc/systemd/system/firewall.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

systemctl daemon-reload && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
systemctl enable firewall.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# Instalacao e configuracao do NTP
#

echo "" | tee -a ${F_LOG} 
echo "Configurando NTP" | tee -a ${F_LOG}

timedatectl set-ntp no && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt install -y ntp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

wget ${REPOSITORY}/ntp/ntp.conf -O /etc/ntp.conf && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# Instalacao do Java/Jetty
#

echo "" | tee -a ${F_LOG} 
echo "Instalando o Java e Jetty" | tee -a ${F_LOG}

wget -O- https://apt.corretto.aws/corretto.key | sudo apt-key add -  && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
add-apt-repository 'deb https://apt.corretto.aws stable main'  && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

echo "JAVA_HOME=\"/usr/lib/jvm/java-11-amazon-corretto\"" >> /etc/environment && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
source /etc/environment && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

apt update; sudo apt install -y java-11-amazon-corretto-jdk && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt install -y jetty9 ; systemctl enable jetty9.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# Instalacao de pacotes
#

echo "" | tee -a ${F_LOG} 
echo "Instalando pacotes" | tee -a ${F_LOG}

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt update && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
apt install -y apache2 libapache2-mod-xforward jetty9 rsyslog filebeat nagios-nrpe-server nagios-plugins && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# OPENSSL - arquivo de config
#

echo "" | tee -a ${F_LOG} 
echo "Gerando arquivo de configuração do OpenSSL" | tee -a ${F_LOG}

cat > /tmp/openssl.cnf <<-EOF
[ req ]
default_bits = 2048 # Size of keys
string_mask = nombstr # permitted characters
distinguished_name = req_distinguished_name
  
[ req_distinguished_name ]
# Variable name   Prompt string
#----------------------   ----------------------------------
0.organizationName = Nome da universidade/organização
organizationalUnitName = Departamento da universidade/organização
emailAddress = Endereço de email da administração
emailAddress_max = 40
localityName = Nome do município (por extenso)
stateOrProvinceName = Unidade da Federação (por extenso)
countryName = Nome do país (código de 2 letras)
countryName_min = 2
countryName_max = 2
commonName = Nome completo do host (incluíndo o domínio)
commonName_max = 64
  
# Default values for the above, for consistency and less typing.
# Variable name   Value
#------------------------------   ------------------------------
0.organizationName_default = ${INITIALS} - ${ORGANIZATION}
emailAddress_default = ${CONTACTMAIL}
organizationalUnitName_default = ${OU}
localityName_default = ${CITY}
stateOrProvinceName_default = ${STATE}
countryName_default = BR
commonName_default = ${HN}.${HN_DOMAIN}
EOF

#
# SHIB - Instalação
#

echo "" | tee -a ${F_LOG} 
echo "Instalando Shibboleth IDP" | tee -a ${F_LOG}

cd /root/
wget https://shibboleth.net/downloads/identity-provider/4.3.0/shibboleth-identity-provider-4.3.0.zip && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
unzip shibboleth-identity-provider-4.3.0.zip && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
${SRCDIR}/bin/install.sh \
-Didp.src.dir=${SRCDIR} \
-Didp.target.dir=${SHIBDIR} \
-Didp.sealer.password=changeit \
-Didp.keystore.password=changeit \
-Didp.conf.filemode=644 \
-Didp.host.name=${HN}.${HN_DOMAIN} \
-Didp.scope=${DOMAIN} \
-Didp.entityID=https://${HN}.${HN_DOMAIN}/idp/shibboleth  && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# OpenSSL - Geração de certificados shib
#

echo "" | tee -a ${F_LOG} 
echo "Gerando certificado digital para o Shibboleth IDP" | tee -a ${F_LOG}

cd ${SHIBDIR}/credentials/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
rm -f idp* && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
openssl genrsa -out idp.key 2048 && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key idp.key -set_serial 00 -config /tmp/openssl.cnf -out idp.crt && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
if [ ${DEBUG} -eq 1 ] ; then
    echo "" 
    echo "Certificado Shibboleth" | tee -a ${F_LOG}
    openssl x509 -in ${SHIBDIR}/credentials/idp.crt -text -noout >> /root/cafe-firstboot.debug | tee -a ${F_LOG}
fi

#
# SHIB - Arquivos estáticos
#

echo "" | tee -a ${F_LOG} 
echo "Obtendo arquivos de configuração estáticos" | tee -a ${F_LOG}

wget ${REPOSITORY}/conf/attribute-filter.xml -O ${SHIBDIR}/conf/attribute-filter.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/attribute-resolver.xml -O ${SHIBDIR}/conf/attribute-resolver.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/metadata-providers.xml -O ${SHIBDIR}/conf/metadata-providers.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/saml-nameid.xml -O ${SHIBDIR}/conf/saml-nameid.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/admin/admin.properties -O ${SHIBDIR}/conf/admin/admin.properties && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/attributes/brEduPerson.xml -O ${SHIBDIR}/conf/attributes/brEduPerson.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/attributes/default-rules.xml -O ${SHIBDIR}/conf/attributes/default-rules.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/attributes/schac.xml -O ${SHIBDIR}/conf/attributes/schac.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/conf/attributes/custom/eduPersonTargetedID.properties -O ${SHIBDIR}/conf/attributes/custom/eduPersonTargetedID.properties && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# SHIB - ldap-properties
#

echo "" | tee -a ${F_LOG} 
echo "Configurando ldap.properties" | tee -a ${F_LOG}

cat > ${SHIBDIR}/conf/ldap.properties <<-EOF
# LDAP authentication (and possibly attribute resolver) configuration
# Note, this doesn't apply to the use of JAAS authentication via LDAP

## Authenticator strategy, either anonSearchAuthenticator, bindSearchAuthenticator, directAuthenticator, adAuthenticator
idp.authn.LDAP.authenticator                    = bindSearchAuthenticator

## Connection properties ##
idp.authn.LDAP.ldapURL                          = ${LDAPSERVERPROTO}${LDAPSERVER}:${LDAPSERVERPORT}
idp.authn.LDAP.useStartTLS                      = false
# Time in milliseconds that connects will block
idp.authn.LDAP.connectTimeout                   = PT3S
# Time in milliseconds to wait for responses
idp.authn.LDAP.responseTimeout                  = PT3S
# Connection strategy to use when multiple URLs are supplied, either ACTIVE_PASSIVE, ROUND_ROBIN, RANDOM
#idp.authn.LDAP.connectionStrategy              = ACTIVE_PASSIVE

## SSL configuration, either jvmTrust, certificateTrust, or keyStoreTrust
idp.authn.LDAP.sslConfig                        = certificateTrust
## If using certificateTrust above, set to the trusted certificate's path
idp.authn.LDAP.trustCertificates                = %{idp.home}/credentials/ldap-server.crt
## If using keyStoreTrust above, set to the truststore path
#idp.authn.LDAP.trustStore                      = %{idp.home}/credentials/ldap-server.truststore

## Return attributes during authentication
idp.authn.LDAP.returnAttributes                 = ${LDAPATTR}

## DN resolution properties ##

# Search DN resolution, used by anonSearchAuthenticator, bindSearchAuthenticator
# for AD: CN=Users,DC=example,DC=org
idp.authn.LDAP.baseDN                           = ${LDAPDN}
idp.authn.LDAP.subtreeSearch                    = ${LDAPSUBTREESEARCH}
idp.authn.LDAP.userFilter                       = (${LDAPATTR}={user})
# bind search configuration
# for AD: idp.authn.LDAP.bindDN=adminuser@domain.com
idp.authn.LDAP.bindDN                           = ${LDAPUSER}

# Format DN resolution, used by directAuthenticator, adAuthenticator
# for AD use idp.authn.LDAP.dnFormat=%s@domain.com
idp.authn.LDAP.dnFormat                         = ${LDAPFORM}

# pool passivator, either none, bind or anonymousBind
#idp.authn.LDAP.bindPoolPassivator              = none

# LDAP attribute configuration, see attribute-resolver.xml
# Note, this likely won't apply to the use of legacy V2 resolver configurations
idp.attribute.resolver.LDAP.ldapURL             = %{idp.authn.LDAP.ldapURL}
idp.attribute.resolver.LDAP.connectTimeout      = %{idp.authn.LDAP.connectTimeout:PT3S}
idp.attribute.resolver.LDAP.responseTimeout     = %{idp.authn.LDAP.responseTimeout:PT3S}
idp.attribute.resolver.LDAP.connectionStrategy  = %{idp.authn.LDAP.connectionStrategy:ACTIVE_PASSIVE}
idp.attribute.resolver.LDAP.baseDN              = %{idp.authn.LDAP.baseDN:undefined}
idp.attribute.resolver.LDAP.bindDN              = %{idp.authn.LDAP.bindDN:undefined}
idp.attribute.resolver.LDAP.useStartTLS         = %{idp.authn.LDAP.useStartTLS:true}
idp.attribute.resolver.LDAP.trustCertificates   = %{idp.authn.LDAP.trustCertificates:undefined}
idp.attribute.resolver.LDAP.searchFilter        = (${LDAPATTR}=\$resolutionContext.principal)

# LDAP pool configuration, used for both authn and DN resolution
#idp.pool.LDAP.minSize                          = 3
#idp.pool.LDAP.maxSize                          = 10
#idp.pool.LDAP.validateOnCheckout               = false
#idp.pool.LDAP.validatePeriodically             = true
#idp.pool.LDAP.validatePeriod                   = PT5M
#idp.pool.LDAP.validateDN                       =
#idp.pool.LDAP.validateFilter                   = (objectClass=*)
#idp.pool.LDAP.prunePeriod                      = PT5M
#idp.pool.LDAP.idleTime                         = PT10M
#idp.pool.LDAP.blockWaitTime                    = PT3S 
EOF

#
# SHIB - secrets.properties
#

echo "" | tee -a ${F_LOG} 
echo "Configurando secrets.properties" | tee -a ${F_LOG}

cat  > ${SHIBDIR}/credentials/secrets.properties <<-EOF
# Access to internal AES encryption key
idp.sealer.storePassword = changeit
idp.sealer.keyPassword = changeit

# Default access to LDAP authn and attribute stores.
idp.authn.LDAP.bindDNCredential              = ${LDAPPWD}
idp.attribute.resolver.LDAP.bindDNCredential = %{idp.authn.LDAP.bindDNCredential:undefined}

# Salt used to generate persistent/pairwise IDs, must be kept secret
idp.persistentId.salt  = ${PERSISTENTDIDSALT}

idp.cafe.computedIDsalt = ${COMPUTEDIDSALT}
EOF

#
# SHIB - idp-properties
#

echo "" | tee -a ${F_LOG} 
echo "Configurando idp.properties" | tee -a ${F_LOG}

cat  > ${SHIBDIR}/conf/idp.properties <<-EOF
idp.searchForProperties= true

idp.additionalProperties= /credentials/secrets.properties

idp.entityID= https://${HN}.${HN_DOMAIN}/idp/shibboleth

idp.scope= ${DOMAIN}
 
idp.csrf.enabled=true

idp.sealer.storeResource=%{idp.home}/credentials/sealer.jks
idp.sealer.versionResource=%{idp.home}/credentials/sealer.kver

idp.signing.key=%{idp.home}/credentials/idp.key
idp.signing.cert=%{idp.home}/credentials/idp.crt
idp.encryption.key=%{idp.home}/credentials/idp.key
idp.encryption.cert=%{idp.home}/credentials/idp.crt

idp.encryption.config=shibboleth.EncryptionConfiguration.GCM

idp.trust.signatures=shibboleth.ExplicitKeySignatureTrustEngine

idp.storage.htmlLocalStorage=true

idp.session.trackSPSessions=true
idp.session.secondaryServiceIndex=true

idp.bindings.inMetadataOrder=false

idp.ui.fallbackLanguages=pt-br,en

idp.fticks.federation = CAFE
idp.fticks.algorithm = SHA-256
idp.fticks.salt = ${FTICKSSALT}
idp.fticks.loghost= localhost
idp.fticks.logport= 514

idp.audit.shortenBindings=true

#idp.loglevel.idp = DEBUG
#idp.loglevel.ldap = DEBUG
#idp.loglevel.messages = DEBUG
#idp.loglevel.encryption = DEBUG
#idp.loglevel.opensaml = DEBUG
#idp.loglevel.props = DEBUG
#idp.loglevel.httpclient = DEBUG
EOF

#
# SHIB - saml-nameid.properties
#

echo "" | tee -a ${F_LOG} 
echo "Configurando saml-nameid.properties" | tee -a ${F_LOG}

cat  > ${SHIBDIR}/conf/saml-nameid.properties <<-EOF
idp.persistentId.sourceAttribute = ${LDAPATTR}
idp.persistentId.encoding = BASE32
EOF

#
# SHIB - idp-metadata.xml
#

echo "" | tee -a ${F_LOG} 
echo "Configurando idp-metadata.xml" | tee -a ${F_LOG}

cp ${SHIBDIR}/credentials/idp.crt /tmp/idp.crt.tmp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
sed -i '$ d' /tmp/idp.crt.tmp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
sed -i 1d /tmp/idp.crt.tmp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
CRT=`cat /tmp/idp.crt.tmp` && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
rm -rf /tmp/idp.crt.tmp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cat > /opt/shibboleth-idp/metadata/idp-metadata.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
 
<EntityDescriptor  xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:xml="http://www.w3.org/XML/1998/namespace" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://${HN}.${HN_DOMAIN}/idp/shibboleth">
 
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">
 
                <Extensions>
                        <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
 
                        <mdui:UIInfo>
                                <mdui:OrganizationName xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:OrganizationName>
                                <mdui:DisplayName xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:DisplayName>
                                <mdui:OrganizationURL xml:lang="en">http://www.${DOMAIN}/</mdui:OrganizationURL>
                        </mdui:UIInfo>
 
                        <md:ContactPerson contactType="technical">
                                <md:SurName>${CONTACT}</md:SurName>
                                <md:EmailAddress>${CONTACTMAIL}</md:EmailAddress>
                        </md:ContactPerson>
                </Extensions>
 
                <KeyDescriptor>
                        <ds:KeyInfo>
                                <ds:X509Data>
                                        <ds:X509Certificate>
${CRT}
                                        </ds:X509Certificate>
                                        </ds:X509Data>
                                </ds:KeyInfo>
                </KeyDescriptor>
 
                <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/ArtifactResolution" index="1"/>
                <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/ArtifactResolution" index="2"/>
                <!--
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/SLO"/>
                -->
                <NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>
                <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
                <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://${HN}.${HN_DOMAIN}/idp/profile/Shibboleth/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SSO"/>
        </IDPSSODescriptor>
 
        <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">

                <Extensions>
                        <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
                </Extensions>

                <KeyDescriptor>
                        <ds:KeyInfo>
                                <ds:X509Data>
                                        <ds:X509Certificate>
${CRT}
                                        </ds:X509Certificate>
                                </ds:X509Data>
                        </ds:KeyInfo>
                </KeyDescriptor>

                <AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/AttributeQuery"/>
                <!-- <AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/AttributeQuery"/> -->
                <!-- If you uncomment the above you should add urn:oasis:names:tc:SAML:2.0:protocol to the protocolSupportEnumeration above -->

        </AttributeAuthorityDescriptor>
</EntityDescriptor>
EOF

#
# SHIB - access-control.xml
#

echo "" | tee -a ${F_LOG} 
echo "Configurando access-control.xml" | tee -a ${F_LOG}

cat > /opt/shibboleth-idp/conf/access-control.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:util="http://www.springframework.org/schema/util"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:c="http://www.springframework.org/schema/c"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
                           http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd"

       default-init-method="initialize"
       default-destroy-method="destroy">

    <util:map id="shibboleth.AccessControlPolicies">

        <entry key="AccessByIPAddress">
            <bean id="AccessByIPAddress" parent="shibboleth.IPRangeAccessControl"
                    p:allowedRanges="#{ {'127.0.0.1/32', '::1/128', '${IP}/32', '${POLLER}/32'} }" />
        </entry>

    </util:map>

</beans>
EOF

#
# SHIB - Personalização layout
#

echo "" | tee -a ${F_LOG} 
echo "Configurando personalizacao de layout" | tee -a ${F_LOG}

#Copiando arquivo para personalizacao
mkdir /tmp/shib-idp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cd /tmp/shib-idp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/layout/pacote-personalizacao-layout-4.1.tar.gz -O /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
tar -zxvf /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
mkdir ${SHIBDIR}/edit-webapp/api && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp /tmp/shib-idp/views/*.vm ${SHIBDIR}/views/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp /tmp/shib-idp/views/client-storage/*.vm ${SHIBDIR}/views/client-storage/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp /tmp/shib-idp/edit-webapp/css/*.css ${SHIBDIR}/edit-webapp/css/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp -R /tmp/shib-idp/edit-webapp/api/* ${SHIBDIR}/edit-webapp/api/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp -R /tmp/shib-idp/edit-webapp/images/* ${SHIBDIR}/edit-webapp/images/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cp /tmp/shib-idp/messages/*.properties ${SHIBDIR}/messages/ && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#Configurando mensagens
setProperty "idp.login.username.label" "${MSG_AUTENTICACAO}" "${SHIBDIR}/messages/messages_pt_BR.properties" && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
setProperty "idp.url.password.reset" "${MSG_URL_RECUPERACAO_SENHA}" "${SHIBDIR}/messages/messages_pt_BR.properties" && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#TODO: mensagens em outras linguas

#Atualizacao do war
${SHIBDIR}/bin/build.sh \
-Didp.target.dir=${SHIBDIR} && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# APACHE - config site, modules e certificados - 01-idp.conf
#

echo "" | tee -a ${F_LOG} 
echo "Configurando Apache" | tee -a ${F_LOG}

wget ${REPOSITORY}/apache/security.conf -O /etc/apache2/conf-available/security.conf && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cat > /etc/apache2/sites-available/01-idp.conf <<-EOF
<VirtualHost ${IP}:80>

    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    Redirect permanent "/" "https://${HN}.${HN_DOMAIN}/"

</VirtualHost>

<VirtualHost ${IP}:443>
 
    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    SSLEngine On
    SSLProtocol -all +TLSv1.1 +TLSv1.2
    SSLCipherSuite ALL:+HIGH:+AES256:+GCM:+RSA:+SHA384:!AES128-SHA256:!AES256-SHA256:!AES128-GCM-SHA256:!AES256-GCM-SHA384:-MEDIUM:-LOW:!SHA:!3DES:!ADH:!MD5:!RC4:!NULL:!DES
    SSLHonorCipherOrder on
    SSLCompression off
    SSLCertificateKeyFile /etc/ssl/private/chave-apache.key
    SSLCertificateFile /etc/ssl/certs/certificado-apache.crt

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port 443
    ProxyPass /idp http://localhost:8080/idp
    ProxyPassReverse /idp http://localhost:8080/idp

    Redirect permanent "/" "https://${URL}/"

</VirtualHost>
EOF

# Chave e Certificado Apache
openssl genrsa -out /etc/ssl/private/chave-apache.key 2048 && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key /etc/ssl/private/chave-apache.key -set_serial 00 \
    -config /tmp/openssl.cnf -out /etc/ssl/certs/certificado-apache.crt && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

if [ ${DEBUG} -eq 1 ] ; then
    echo "" 
    echo "Certificado Apache" | tee -a ${F_LOG}
    openssl x509 -in /etc/ssl/certs/certificado-apache.crt -text -noout >> /root/cafe-firstboot.debug | tee -a ${F_LOG}
fi

chown root:ssl-cert /etc/ssl/private/chave-apache.key /etc/ssl/certs/certificado-apache.crt && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chmod 640 /etc/ssl/private/chave-apache.key && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

a2dissite 000-default.conf && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
a2enmod ssl headers proxy_http && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
a2ensite 01-idp.conf && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
systemctl restart apache2 && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# FTICKS - Filebeat / rsyslog
#

echo "" | tee -a ${F_LOG} 
echo "Configurando FTICKS" | tee -a ${F_LOG}

cat > /etc/rsyslog.conf <<-EOF
#  /etc/rsyslog.conf    Configuration file for rsyslog.
#
#                       For more information see
#                       /usr/share/doc/rsyslog-doc/html/rsyslog_conf.html
#
#  Default logging rules can be found in /etc/rsyslog.d/50-default.conf

#################
#### MODULES ####
#################

#module(load="imuxsock") # provides support for local system logging
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
#\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Filter duplicated messages
\$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
\$FileOwner syslog
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022
\$PrivDropToUser syslog
\$PrivDropToGroup syslog

#
# Where to place spool and state files
#
\$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
\$IncludeConfig /etc/rsyslog.d/*.conf
EOF

cat > /etc/rsyslog.d/01-fticks.conf <<-EOF
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" /var/log/fticks.log
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" ~
EOF

touch /var/log/fticks.log && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chmod 0640 /var/log/fticks.log && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chown syslog:adm /var/log/fticks.log && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
systemctl restart rsyslog && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cat > /etc/filebeat/filebeat.yml <<-EOF
#============================ Filebeat inputs ================================

filebeat.inputs:

- type: log

  enabled: true

  paths:
    - /var/log/fticks.log

#============================= Filebeat modules ==============================

filebeat.config.modules:

  path: \${path.config}/modules.d/*.yml

  reload.enabled: false

#----------------------------- Logstash output --------------------------------

output.logstash:
  hosts: ["estat-ls.cafe.rnp.br:5044"]

#================================ Processors ==================================

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
EOF

systemctl restart filebeat && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
systemctl enable filebeat && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

cat > /etc/logrotate.d/fticks <<-EOF
/var/log/fticks.log {
    su root root
    create 0640 syslog adm
    daily
    rotate 180
    compress
    nodelaycompress
    dateext
    missingok
    postrotate
        systemctl restart rsyslog
    endscript
}
EOF

#
# FAIL2BAN
#

echo "" | tee -a ${F_LOG} 
echo "Configurando Fail2ban" | tee -a ${F_LOG}

apt install -y fail2ban && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
cat > /etc/fail2ban/filter.d/shibboleth-idp.conf <<-EOF
# Fail2Ban filter for Shibboleth IDP
#
# Author: rui.ribeiro@cafe.rnp.br
#
[INCLUDES]
before          = common.conf

[Definition]
_daemon         = jetty
failregex       = <HOST>.*Login by.*failed
EOF

cat > /etc/fail2ban/jail.local <<-EOF
[shibboleth-idp]
enabled = true
filter = shibboleth-idp
port = all
banaction = iptables-allports
logpath = /opt/shibboleth-idp/logs/idp-process.log
findtime = 300
maxretry = 5
EOF

#
# KEYSTORE - Popular com certificados
#

# Se LDAP usa SSL, pega certificado e adiciona no keystore
if [ ${LDAPSERVERSSL} -eq 1 ] ; then

    echo "" | tee -a ${F_LOG} 
    echo "Configurando Certificados LDAPS" | tee -a ${F_LOG}
    
    openssl s_client -showcerts -connect ${LDAPSERVER}:${LDAPSERVERPORT} < /dev/null 2> /dev/null | openssl x509 -outform PEM > /opt/shibboleth-idp/credentials/ldap-server.crt && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
    /usr/lib/jvm/java-11-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /usr/lib/jvm/java-11-amazon-corretto/lib/security/cacerts -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
    /usr/lib/jvm/java-11-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /opt/shibboleth-idp/credentials/ldap-server.truststore -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
    sed -i -e 's/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\"/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\" trustFile=\"%{idp.attribute.resolver.LDAP.trustCertificates}\"/' /opt/shibboleth-idp/conf/attribute-resolver.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
fi

#
# RNP - Monitoramento
#

echo "" | tee -a ${F_LOG} 
echo "Configurando Monitoramento RNP" | tee -a ${F_LOG}

cat > /etc/nagios/nrpe.cfg <<-EOF
log_facility=daemon
debug=0
pid_file=/run/nagios/nrpe.pid
server_port=5666
nrpe_user=nagios
nrpe_group=nagios
allowed_hosts=127.0.0.1,::1,${IP},${POLLER}
dont_blame_nrpe=0
allow_bash_command_substitution=0
command_timeout=60
connection_timeout=300
disable_syslog=0

## Configuracao de infra do IDP
command[check_load]=/usr/lib/nagios/plugins/check_load -r -w .40,.35,.30 -c .60,.55,.50
command[check_sda1]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /dev/sda1
command[check_mem]=/usr/lib/nagios/plugins/check_mem
command[check_uptime]=/usr/lib/nagios/plugins/check_uptime
command[check_http]=/usr/lib/nagios/plugins/check_tcp -p 80
command[check_https]=/usr/lib/nagios/plugins/check_tcp -p 443
 
## Configuracao de uso do status page.
command[check_idp_uptime]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpuptime
command[check_idp_status]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpstatus
command[check_idp_lastmetadata]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idplastmetadata
command[check_idp_idpversion]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpversion
command[check_idp_jdkversion]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" jdkversion

include=/etc/nagios/nrpe_local.cfg
include_dir=/etc/nagios/nrpe.d/
EOF

# Download de checks
wget ${REPOSITORY}/nagios/check_idp -O /usr/lib/nagios/plugins/check_idp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/nagios/check_mem -O /usr/lib/nagios/plugins/check_mem && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/nagios/check_uptime -O /usr/lib/nagios/plugins/check_uptime && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

# Corrige permissões
chmod 755 /usr/lib/nagios/plugins/check_idp && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chmod 755 /usr/lib/nagios/plugins/check_mem && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
chmod 755 /usr/lib/nagios/plugins/check_uptime && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

systemctl restart nagios-nrpe-server.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

#
# JETTY - Configuração
#

echo "" | tee -a ${F_LOG} 
echo "Configurando Jetty" | tee -a ${F_LOG}

sed -i 's/^ReadWritePaths=\/var\/lib\/jetty9\/$/ReadWritePaths=\/var\/lib\/jetty9\/ \/opt\/shibboleth-idp\/credentials\/ \/opt\/shibboleth-idp\/logs\/ \/opt\/shibboleth-idp\/metadata\//' /lib/systemd/system/jetty9.service && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
systemctl daemon-reload && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
wget ${REPOSITORY}/jetty/idp.ini -O /etc/jetty9/start.d/idp.ini && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}
sed -i '/<param-name>dirAllowed<\/param-name>/!b;n;c\ \ \ \ \ \ <param-value>false<\/param-value>' /etc/jetty9/webdefault.xml && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

# Corrige permissões
chown -R jetty:jetty ${SHIBDIR}/{credentials,logs,metadata} && echo "OK" | tee -a ${F_LOG} || echo "ERRO" | tee -a ${F_LOG}

# Configura contexto no Jetty
cat > /var/lib/jetty9/webapps/idp.xml <<-EOF
<Configure class="org.eclipse.jetty.webapp.WebAppContext">
  <Set name="war">${SHIBDIR}/war/idp.war</Set>
  <Set name="contextPath">/idp</Set>
  <Set name="extractWAR">false</Set>
  <Set name="copyWebDir">false</Set>
  <Set name="copyWebInf">true</Set>
  <Set name="persistTempDirectory">false</Set>
</Configure>
EOF

#
# Reinicialização
#

echo "" | tee -a ${F_LOG} 
echo "Reinicializando sistema" | tee -a ${F_LOG}
echo "`date`" | tee -a ${F_LOG}

reboot