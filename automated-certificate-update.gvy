pipeline {
    agent { label 'built-in' }

    parameters {
        choice(
            name: 'DOMAIN',
            choices: [
                '*.my-certificate-name.net' 
            ],
            description: 'Select Certificate Name Renew and Update in place ... '
        )
    }

    environment {

    AWS_REGION = "us-west-2"
    PFX_PASS = "your_pfx_password"
    JENKINS_PFX_PASS = "your_jenkins_pfx_password"
    my-company-name_PROD_SERVER_IP = "192.168.1.5,192.168.1.6"
    ZABBIX_PROD_SERVER_IP = "192.168.1.7"
    JENKINS_LINUX_SERVER_IP = "192.168.1.8"

    CERTIFICATE_UPDATE_STATUS = false   
    
    }

    stages {
        stage('Domain') {
            steps {
                echo "You selected: ${params.DOMAIN}"
            }
        }

    stage('DetermineValidityPeriod') {
        steps {
            script {
                def baseDomain = params.DOMAIN.replaceFirst(/\*\./, '')  // Remove "*."
                def subdomain = ""

                switch (baseDomain) {
                    case "my-certificate-name.net":
                        subdomain = "zabbix"
                        break                                               
                    default:
                        error "No mapping defined for base domain: ${baseDomain}"
                }

                def finalDomain = "${subdomain}.${baseDomain}"
                echo "Mapped Domain: ${finalDomain}"
                def scriptPath = 'my-git/repo-name/with-path/certificate-update/ssl.ps1'
                // Run PowerShell script and capture output
                def output = bat(
                    script: """
                    powershell -NoProfile -ExecutionPolicy Bypass -File "${scriptPath}" -Domain "${finalDomain}" 2>&1
                    """,
                    returnStdout: true
                ).trim()
                
                echo "Raw script output:\n${output}"
                
                def daysLeft = 0
                for (line in output.readLines()) {
                    if (line.trim() ==~ /^\d+$/) {
                        daysLeft = line.trim().toInteger()
                        break
                    }
                }
                echo "Parsed days left: ${daysLeft}"
                if (daysLeft == 0) {
                    echo "SSL certificate is invalid or not accessible."
                    CERTIFICATE_UPDATE_STATUS = true
                } else if (daysLeft < 15) {
                    echo "SSL certificate is about to expire soon (less than 10 days)."
                    CERTIFICATE_UPDATE_STATUS = true
                } else {
                    echo "SSL certificate validity is greater then 10 / we have some issues "
                    CERTIFICATE_UPDATE_STATUS = false 
                }

            }
        }
    }


    stage('StartInstance') {
        when {
                expression { CERTIFICATE_UPDATE_STATUS } // Proceed only if validity is less 
            }            
            steps {
                script {
                    // Map domain to instance ID
                    def instanceId = ''
                    switch(params.DOMAIN) {
                        case '*.my-certificate-name.net':
                            instanceId = "['i-3f8b71c9d4eaaf235', 'i-7a12de90b5ccfa842']"
                            break                            
                        default:
                            echo "No instance mapping found for domain: ${params.DOMAIN}"
                    }

                    if (instanceId) {
                        echo "Using instance ID: ${instanceId}"
                        withCredentials([
                            [$class: 'UsernamePasswordMultiBinding',
                                credentialsId: 'jenkins-aws-credentials-id',
                                usernameVariable: 'AWS_ACCESS_KEY',
                                passwordVariable: 'AWS_SECRET_KEY']
                        ]) {
                            def scriptPath = 'my-git/repo-name/with-path/certificate-update/start-mainline-rc.py'
                            // Run Python and capture exit code without failing Jenkins automatically
                            def exitCode = bat(
                                script: """
                                    "python.exe" ${scriptPath} %AWS_ACCESS_KEY% %AWS_SECRET_KEY% ${AWS_REGION} "${instanceId}"
                                """,
                                returnStatus: true
                            )

                            if (exitCode != 0) {
                                error "Python script failed with exit code ${exitCode}"
                            } else {
                                echo "Instance started and passed all status checks."
                            }
                        }                        
                    } else {
                        echo "Move on to next ..."
                    }


                }
            }
        }
    



    stage('UpdateCertificate')
    {
        when {
                expression { CERTIFICATE_UPDATE_STATUS } // Proceed only if validity is less 
            }
        steps
        {
            script
            {
                try
                {
                    withCredentials([
                    [$class: 'UsernamePasswordMultiBinding', 
                    credentialsId: 'jenkins-aws-credentials-id', 
                    usernameVariable: 'AWS_KEY', 
                    passwordVariable: 'AWS_SECRET']
                    ]) 
                    {
                        def resultOutput = powershell (
                            script: "powershell -NoProfile -ExecutionPolicy Bypass -File 'my-git/repo-name/with-path/certificate-update/backup-create-cert.ps1' -Domain '${params.DOMAIN}' -AccessKey '${AWS_KEY}' -SecretKey '${AWS_SECRET}' -PfxPass '${PFX_PASS}'",
                            returnStdout: true
                        ).trim()

                        echo "Raw Output: ${resultOutput}"

                        // Detect result
                        if (resultOutput.contains('[RESULT] NEW_CERT')) {
                            echo "New certificate created"
                        } else if (resultOutput.contains('[RESULT] REUSED_CERT')) {
                            echo "Certificate already existed and was reused"
                        } else {
                            error "Could not detect result"
                        }   
                    }
                } catch (err) 
                {
                    echo "Script failed with error: ${err.getMessage()}"
                    currentBuild.result = 'FAILURE'
                    throw err // rethrow to fail the build
                }
            }
        }
    } // end of Stage


    stage('UpdateACM') {
        when {
                expression { CERTIFICATE_UPDATE_STATUS } // Proceed only if validity is less 
            }
        steps{
            script{
                def domain = params.DOMAIN           // e.g., *.my-company-name-01.com
                def escapedDomain = domain.replace('*', '!')
                def certPathGlob = "${env.LOCALAPPDATA}\\Posh-ACME\\LE_PROD\\*\\${escapedDomain}"
                echo "Certificate path glob: ${certPathGlob}"

                withCredentials([
                    [$class: 'UsernamePasswordMultiBinding',
                        credentialsId: 'jenkins-aws-credentials-id',
                        usernameVariable: 'AWS_ACCESS_KEY',
                        passwordVariable: 'AWS_SECRET_KEY']
                ]) {
                    def scriptPath = 'my-git/repo-name/with-path/certificate-update/update-aws-certificate.py'
                    // Run Python and capture exit code without failing Jenkins automatically
                    def exitCode = bat(
                        script: """
                            "python.exe" ${scriptPath} %AWS_ACCESS_KEY% %AWS_SECRET_KEY% "${params.DOMAIN}"
                        """,
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        error "Python script failed with exit code ${exitCode}"
                    } else {
                        echo "Certificates updated in AWS Certificate Manager"
                    }
                }    


            }

        }
    } 

    stage('UpdateHOST'){
        when {
                expression { CERTIFICATE_UPDATE_STATUS } // Proceed only if validity is less 
            }
        steps{
            script{

                def baseDomain = params.DOMAIN.replaceFirst(/\*\./, '')  // Remove "*."
                def subdomain = ""

                switch (baseDomain) {
                    case "my-certificate-name.net":

                        def ipList = env.my-company-name_PROD_SERVER_IP.split(',')
                        ipList.each { ip ->
                            echo "Deploying to IP: ${ip}"

                            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'jenkins-windows-remote-admin-id', 
                            usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']])
                            {
                                def result_host_update = powershell(returnStatus: true, script: """
                                    & 'my-git/repo-name/with-path/certificate-update/update-iis-robust.ps1' -RemoteIP "${ip}" `
                                                        -Username "${USERNAME}" `
                                                        -Password "${PASSWORD}" `
                                                        -CertCN ${params.DOMAIN} `
                                                        -PfxPassword ${PFX_PASS} `
                                                        -ConfirmDeletion `
                                                        -DebugOutput
                                """)
                                if (result_host_update != 0) {
                                    error "PowerShell script failed to update the certificate ${params.DOMAIN} on server ${ip}!"
                                }
                            }// End of With Credentials                               
                        }

                        def SCRIPT_PATH = 'my-git/repo-name/with-path/certificate-update/update-jenkins-windows.ps1'
                    
                        try {
                            // Execute PowerShell with error handling
                            def psExitCode = powershell(
                                returnStatus: true,
                                script: """
                                    try {
                                        Write-Host "Starting certificate update for domain: ${params.DOMAIN}"
                                        
                                        & "${SCRIPT_PATH}" `
                                            -CertCN '${params.DOMAIN}' `
                                            -JksPassword (ConvertTo-SecureString -AsPlainText -Force -String '$env.JENKINS_PFX_PASS') `
                                            -PfxPassword (ConvertTo-SecureString -AsPlainText -Force -String '$env.PFX_PASS')
                                        
                                        if (\$LASTEXITCODE -ne 0) {
                                            throw "PowerShell script failed with exit code \$LASTEXITCODE"
                                        }
                                        Write-Host "Successfully updated certificates"
                                        exit 0
                                    } catch {
                                        Write-Host "##[error]Error during execution: \$_"
                                        exit 1
                                    }
                                """
                            )

                            if (psExitCode != 0) {
                                error("Jenkins Certificate update failed with exit code ${psExitCode}")
                            }

                        } catch (Exception e) {
                            echo "##[error]Pipeline failed: ${e.getMessage()}"
                            currentBuild.result = 'FAILURE'
                            throw e  // Re-throw to mark stage as failed
                        }

                        try {
                            def scriptPath = 'my-git/repo-name/with-path/certificate-update/update-jenkins-linux.py'  // Windows path
                            // Run Python and capture exit code without failing Jenkins automatically
                            def exitCode = bat(
                                script: """
                                    "python.exe" ${scriptPath} "${params.DOMAIN}" "${JENKINS_LINUX_SERVER_IP}"
                                """,
                                returnStatus: true
                            )
                        } catch (Exception e) {
                            echo "PIPELINE FAILURE: ${e.getMessage()}"
                            error("Certificate deployment pipeline failed")
                        } finally {
                            echo "--------------------------------------------------"
                            echo "Deployment process completed (status: ${currentBuild.result ?: 'SUCCESS'})"
                            echo "--------------------------------------------------"
                        }   


                        try {
                            def scriptPath = 'my-git/repo-name/with-path/certificate-update/update-zabbix-certificate.py'  // Windows path
                            // Run Python and capture exit code without failing Jenkins automatically
                            def exitCode = bat(
                                script: """
                                    "python.exe" ${scriptPath} "${params.DOMAIN}" "${ZABBIX_PROD_SERVER_IP}"
                                """,
                                returnStatus: true
                            )
                        } catch (Exception e) {
                            echo "PIPELINE FAILURE: ${e.getMessage()}"
                            error("Certificate deployment pipeline failed")
                        } finally {
                            echo "--------------------------------------------------"
                            echo "Deployment process completed (status: ${currentBuild.result ?: 'SUCCESS'})"
                            echo "--------------------------------------------------"
                        }   

                        break                                               
                    default:
                        error "No mapping defined for base domain: ${baseDomain}"
                }                



            }
        }
    }   // End Of Stage Updated Host 


    stage('SendMail'){
        when {
                expression { CERTIFICATE_UPDATE_STATUS } // Proceed only if validity is less 
            }
        steps{
            script{

                def baseDomain = params.DOMAIN.replaceFirst(/\*\./, '')  // Remove "*."
                def subdomain = ""

                switch (baseDomain) {
                    case "my-certificate-name.net":
                        def TO_LIST = "devops@my-company.com"
                        def CC_LIST = "mscops@my-company.com; sarowar@my-company.com; sarowar@my-company.com"
                        def AWS_REGION = "us-east-1"
                        def bucket_name = "marcombox-logs"
                        def bucket_prefix = "certificates/"

                        try {
                            withCredentials([
                                [$class: 'UsernamePasswordMultiBinding',
                                credentialsId: 'f7921b08-4448-4862-9aec-75365b928acf',
                                usernameVariable: 'AWS_KEY',
                                passwordVariable: 'AWS_SECRET'], 
                        
                                [$class: 'UsernamePasswordMultiBinding', 
                                credentialsId: 'ac8c82cf-4f92-4903-86c6-8985cf7e009c', 
                                usernameVariable: 'AWS_KEY2', 
                                passwordVariable: 'AWS_SECRET2']
                            ]) {
                                def scriptPath = 'my-git/repo-name/with-path/certificate-update/send_certificate_email.py'
                                def command = "python.exe \"${scriptPath}\" \"${params.DOMAIN}\" \"${TO_LIST}\" \"${CC_LIST}\" \"%AWS_KEY%\" \"%AWS_SECRET%\" \"${AWS_REGION}\" \"%AWS_KEY2%\" \"%AWS_SECRET2%\" \"${bucket_name}\" \"${bucket_prefix}\"  "

                                echo "[INFO] Running: ${command}"
                                bat command
                            }
                        } catch (err) {
                            echo "[ERROR] Python script failed: ${err}"
                            currentBuild.result = 'UNSTABLE'
                        }
                        break                                               
                    default:
                        error "No mapping defined for base domain: ${baseDomain}"
                }                



            }
        }
    }   // End Of Stage Send Mail 
    } // Stages 

post {
    always {
        script {
            try {
                // Workspace cleanup
                if (fileExists(env.WORKSPACE)) {
                    echo "Cleaning up workspace: ${env.WORKSPACE}"
                    deleteDir()
                    cleanWs(
                        cleanWhenNotBuilt: false,
                        deleteDirs: true,
                        disableDeferredWipeout: true,
                        notFailBuild: true,
                        patterns: [
                            [pattern: '.gitignore', type: 'INCLUDE'],
                            [pattern: '.propsfile', type: 'EXCLUDE']
                        ]
                    )
                }
            } catch (Exception e) {
                echo "WARNING: Cleanup failed - ${e.message}"
            }
        }
    }

failure {
    script {
        try {
            withCredentials([[
                $class: 'UsernamePasswordMultiBinding',
                credentialsId: 'f7921b08-4448-4862-9aec-75365b928acf',
                usernameVariable: 'AWS_ACCESS_KEY_ID',
                passwordVariable: 'AWS_SECRET_ACCESS_KEY'
            ]]) {
                // Define recipients
                def toRecipients = "'mscops@my-company.com'"
                def ccRecipients = "'karim@my-company.com', 'rahim@my-company.com'"
                
                // Get error message
                def errorMsg = currentBuild.rawBuild.getLog(100).findAll { 
                    it.contains('ERROR') || it.contains('FAIL') || it.contains('Exception') 
                }.join('\n')
                if (!errorMsg) {
                    errorMsg = "No specific error message captured (check build logs)"
                }

                // Create the properly indented Python script
                def pythonScript = """\
import boto3
import os

def send_email_SES():
    AWS_REGION = 'us-east-1'
    SENDER_EMAIL = 'DevOps_Jankins_Automation <noreply@my-certificate-name.net>'
    TO_RECIPIENTS = [${toRecipients}]
    CC_RECIPIENTS = [${ccRecipients}]
    SUBJECT = 'FAILED: ${env.JOB_NAME.replace("'", "\\\\'")} #${env.BUILD_NUMBER}'
    ERROR_MESSAGE = '''${errorMsg.replace("'", "\\\\'")}'''
    
    session = boto3.Session(
        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
    )
    ses_client = session.client('ses', region_name=AWS_REGION)
    
    try:
        response = ses_client.send_email(
            Destination={
                'ToAddresses': TO_RECIPIENTS,
                'CcAddresses': CC_RECIPIENTS
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': 'UTF-8',
                        'Data': f'''<html>
                            <body>
                                <h2>Build Failed</h2>
                                <p><strong>Job:</strong> ${env.JOB_NAME.replace("'", "\\\\'")}</p>
                                <p><strong>Build:</strong> #${env.BUILD_NUMBER}</p>
                                <p><strong>Console:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                                <hr>
                                <h3>Error Details:</h3>
                                <pre style="background:#f5f5f5;padding:10px;border-radius:5px;">{ERROR_MESSAGE}</pre>
                            </body>
                        </html>'''
                    }
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': SUBJECT
                },
            },
            Source=SENDER_EMAIL,
        )
        print('Email sent! Message ID:', response['MessageId'])
    except Exception as e:
        print('Email sending failed:', str(e))
        raise

send_email_SES()
""".stripIndent()

                // Write and execute
                writeFile file: 'send_email_temp.py', text: pythonScript
                def output = bat(script: "python send_email_temp.py", returnStdout: true).trim()
                echo "Email sending output: ${output}"
                bat "del send_email_temp.py"
                
                if (output.contains("Email sending failed")) {
                    error("Failed to send notification email")
                }
            }
        } catch (Exception e) {
            echo "ERROR: Failed to send failure notification - ${e.message}"
        }
    }
}
} // End of Post Cleanup and Mail of Failure 


}// End od Pipeline 