pipeline {
    agent { label 'built-in' }

    parameters {
        choice(
            name: 'DOMAIN',
            choices: [
                '*.service-x.example.com' 
            ],
            description: 'Select Certificate Name Renew and Update in place ... '
        )
    }

    environment {

    AWS_REGION = "us-west-2"
    PFX_PASS = "your_pfx_password"
    JENKINS_PFX_PASS = "your_jenkins_pfx_password"
    COMPANY_A_PROD_SERVER_IP = "10.0.1.10,10.0.1.11"
    ZABBIX_PROD_SERVER_IP = "10.0.1.20"
    JENKINS_LINUX_SERVER_IP = "10.0.1.30"

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
                    case "service-x.example.com":
                        subdomain = "zabbix"
                        break                                               
                    default:
                        error "No mapping defined for base domain: ${baseDomain}"
                }

                def finalDomain = "${subdomain}.${baseDomain}"
                echo "Mapped Domain: ${finalDomain}"
                def scriptPath = 'git/repo-y/certificate-automation/ssl.ps1'
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
                        case '*.service-x.example.com':
                            instanceId = "['i-1234567890abcdef0', 'i-0fedcba0987654321']"
                            break                            
                        default:
                            echo "No instance mapping found for domain: ${params.DOMAIN}"
                    }

                    if (instanceId) {
                        echo "Using instance ID: ${instanceId}"
                        withCredentials([
                            [$class: 'UsernamePasswordMultiBinding',
                                credentialsId: 'jenkins-aws-creds-id',
                                usernameVariable: 'AWS_ACCESS_KEY',
                                passwordVariable: 'AWS_SECRET_KEY']
                        ]) {
                            def scriptPath = 'git/repo-y/certificate-automation/start-mainline-rc.py'
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
                    credentialsId: 'jenkins-aws-creds-id', 
                    usernameVariable: 'AWS_KEY', 
                    passwordVariable: 'AWS_SECRET']
                    ) 
                    {
                        def resultOutput = powershell (
                            script: "powershell -NoProfile -ExecutionPolicy Bypass -File 'git/repo-y/certificate-automation/backup-create-cert.ps1' -Domain '${params.DOMAIN}' -AccessKey '${AWS_KEY}' -SecretKey '${AWS_SECRET}' -PfxPass '${PFX_PASS}'",
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
                def domain = params.DOMAIN           // e.g., *.company-a-prod.example.com
                def escapedDomain = domain.replace('*', '!')
                def certPathGlob = "${env.LOCALAPPDATA}\\Posh-ACME\\LE_PROD\\*\\${escapedDomain}"
                echo "Certificate path glob: ${certPathGlob}"

                withCredentials([
                    [$class: 'UsernamePasswordMultiBinding',
                        credentialsId: 'jenkins-aws-creds-id',
                        usernameVariable: 'AWS_ACCESS_KEY',
                        passwordVariable: 'AWS_SECRET_KEY']
                ]) {
                    def scriptPath = 'git/repo-y/certificate-automation/update-aws-certificate.py'
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
                    case "service-x.example.com":

                        def ipList = env.COMPANY_A_PROD_SERVER_IP.split(',')
                        ipList.each { ip ->
                            echo "Deploying to IP: ${ip}"

                            withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'jenkins-win-admin-id', 
                            usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']])
                            {
                                def result_host_update = powershell(returnStatus: true, script: """
                                    & 'git/repo-y/certificate-automation/update-iis-robust.ps1' -RemoteIP "${ip}" `
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

                        def SCRIPT_PATH = 'git/repo-y/certificate-automation/update-jenkins-windows.ps1'
                    
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
                            def scriptPath = 'git/repo-y/certificate-automation/update-jenkins-linux.py'  // Windows path
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
                            def scriptPath = 'git/repo-y/certificate-automation/update-zabbix-certificate.py'  // Windows path
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
                    case "service-x.example.com":
                        def TO_LIST = "devops@company-a.example.com"
                        def CC_LIST = "ops-team@company-a.example.com; user-1@company-a.example.com; user-1@company-a.example.com"
                        def AWS_REGION = "us-east-1"
                        def bucket_name = "company-a-logs"
                        def bucket_prefix = "certificates/"

                        try {
                            withCredentials([
                                [$class: 'UsernamePasswordMultiBinding',
                                credentialsId: 'aws-creds-id-1',
                                usernameVariable: 'AWS_KEY',
                                passwordVariable: 'AWS_SECRET'], 
                        
                                [$class: 'UsernamePasswordMultiBinding', 
                                credentialsId: 'aws-creds-id-2', 
                                usernameVariable: 'AWS_KEY2', 
                                passwordVariable: 'AWS_SECRET2']
                            ]) {
                                def scriptPath = 'git/repo-y/certificate-automation/send_certificate_email.py'
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
                credentialsId: 'aws-creds-id-1',
                usernameVariable: 'AWS_ACCESS_KEY_ID',
                passwordVariable: 'AWS_SECRET_ACCESS_KEY'
            ]]) {
                // Define recipients
                def toRecipients = "'ops-team@company-a.example.com'"
                def ccRecipients = "'user-2@company-a.example.com', 'user-3@company-a.example.com'"
                
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
    SENDER_EMAIL = 'DevOps_Jenkins_Automation <noreply@service-x.example.com>'
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