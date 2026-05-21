// ============================================================================
// Mobile Security Pipeline
// Maintained by the Security Team — security-pipeline/mobile-security-pipeline
//
// Scans Android APK files using MobSF Static Analysis REST API.
// Supports: APK files committed to the repository.
//
// Required Jenkins job parameters:
//   REPO_NAME         — Repository name (no spaces, use hyphens)
//   GITLAB_PROJECT_ID — Numeric GitLab project ID
//   GITLAB_REPO_PATH  — Repository path e.g. group/repo-name
//   APK_PATH          — Path to APK file relative to repo root (optional)
//                       If empty, pipeline auto-detects the first *.apk found
//
// Required Jenkins credentials:
//   jenkins-ci-checkout  — Username/password for repository checkout
//   security-group-token — Group Access Token for this pipeline repo
//   gitlab-api-token     — GitLab API token for posting commit comments
//   mobsf-api-key        — MobSF REST API key
// ============================================================================

pipeline {
    agent any

    environment {
        GITLAB_HOST  = 'http://gitlab.internal'
        MOBSF_HOST   = 'http://mobsf.internal:8000'
    }

    stages {

        // ── Stage 1: Validate ─────────────────────────────────────────────
        stage('Validate configuration') {
            steps {
                script {
                    if (!env.REPO_NAME) {
                        error "REPO_NAME is not set."
                    }
                    if (!env.GITLAB_PROJECT_ID) {
                        error "GITLAB_PROJECT_ID is not set."
                    }
                    if (!env.GITLAB_REPO_PATH) {
                        error "GITLAB_REPO_PATH is not set."
                    }
                    if (env.REPO_NAME.contains(' ')) {
                        error "REPO_NAME '${env.REPO_NAME}' contains spaces. Use hyphens instead."
                    }
                    echo "Running mobile security pipeline for: ${env.REPO_NAME}"
                    echo "GitLab project ID: ${env.GITLAB_PROJECT_ID}"
                    echo "Repository path: ${env.GITLAB_REPO_PATH}"
                    echo "MobSF host: ${env.MOBSF_HOST}"
                }
            }
        }

        // ── Stage 2: Checkout ─────────────────────────────────────────────
        stage('Checkout mobile repository') {
            steps {
                script {
                    // Save report generator before workspace is overwritten
                    sh 'cp generate-mobile-report.py /tmp/generate-mobile-report.py'

                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: '*/main']],
                        userRemoteConfigs: [[
                            url: "${env.GITLAB_HOST}/${env.GITLAB_REPO_PATH}.git",
                            credentialsId: 'jenkins-ci-checkout'
                        ]]
                    ])

                    env.REPO_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                    echo "Mobile repository commit: ${env.REPO_COMMIT}"
                }
            }
        }

        // ── Stage 3: Detect APK ───────────────────────────────────────────
        stage('Detect APK file') {
            steps {
                script {
                    def apkPath = env.APK_PATH?.trim()

                    if (apkPath) {
                        // Use the path provided as parameter
                        if (!fileExists(apkPath)) {
                            error "APK file not found at specified path: ${apkPath}"
                        }
                        env.APK_FILE = apkPath
                        echo "Using specified APK: ${apkPath}"
                    } else {
                        // Auto-detect first APK in repository
                        def found = sh(
                            script: 'find . -name "*.apk" -not -path "./.git/*" | head -1',
                            returnStdout: true
                        ).trim()

                        if (!found) {
                            error "No APK file found in repository. Commit an APK file or set the APK_PATH parameter."
                        }
                        env.APK_FILE = found
                        echo "Auto-detected APK: ${found}"
                    }

                    // Get APK filename and size
                    env.APK_NAME = sh(
                        script: "basename '${env.APK_FILE}'",
                        returnStdout: true
                    ).trim()
                    env.APK_SIZE = sh(
                        script: "du -sh '${env.APK_FILE}' | cut -f1",
                        returnStdout: true
                    ).trim()

                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "APK file   : ${env.APK_FILE}"
                    echo "APK name   : ${env.APK_NAME}"
                    echo "APK size   : ${env.APK_SIZE}"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                }
            }
        }

        // ── Stage 4: Upload APK to MobSF ─────────────────────────────────
        stage('Upload APK to MobSF') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'mobsf-api-key', variable: 'MOBSF_KEY')]) {
                        def uploadResponse = sh(
                            script: """
                                curl -s -F "file=@${env.APK_FILE}" \
                                  -H "X-Mobsf-Api-Key: \${MOBSF_KEY}" \
                                  ${env.MOBSF_HOST}/api/v1/upload
                            """,
                            returnStdout: true
                        ).trim()

                        echo "Upload response: ${uploadResponse}"

                        def uploadJson = readJSON text: uploadResponse
                        if (!uploadJson.hash) {
                            error "Upload failed — no hash returned. Response: ${uploadResponse}"
                        }

                        env.MOBSF_HASH     = uploadJson.hash
                        env.MOBSF_FILE_NAME = uploadJson.file_name ?: env.APK_NAME
                        env.MOBSF_SCAN_TYPE = uploadJson.scan_type ?: 'apk'

                        echo "Upload successful"
                        echo "MobSF hash: ${env.MOBSF_HASH}"
                        echo "Scan type : ${env.MOBSF_SCAN_TYPE}"
                    }
                }
            }
        }

        // ── Stage 5: Run MobSF scan ───────────────────────────────────────
        stage('Run MobSF static analysis') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'mobsf-api-key', variable: 'MOBSF_KEY')]) {
                        echo "Starting MobSF static analysis..."

                        def scanResponse = sh(
                            script: """
                                curl -s -X POST \
                                  -H "X-Mobsf-Api-Key: \${MOBSF_KEY}" \
                                  -H "Content-Type: application/x-www-form-urlencoded" \
                                  --data-urlencode "hash=${env.MOBSF_HASH}" \
                                  --data-urlencode "scan_type=${env.MOBSF_SCAN_TYPE}" \
                                  --data-urlencode "file_name=${env.MOBSF_FILE_NAME}" \
                                  ${env.MOBSF_HOST}/api/v1/scan
                            """,
                            returnStdout: true
                        ).trim()

                        // MobSF scan can take 1-5 minutes depending on APK size
                        // The scan response contains the full results when complete
                        def scanJson = readJSON text: scanResponse

                        if (scanJson.error) {
                            error "MobSF scan failed: ${scanJson.error}"
                        }

                        // Save full scan response for report generation
                        writeFile file: 'mobsf-scan.json', text: scanResponse
                        archiveArtifacts artifacts: 'mobsf-scan.json', allowEmptyArchive: true

                        echo "MobSF static analysis complete"

                        // Extract key metrics
                        def securityScore = scanJson.appsec?.security_score ?: 'N/A'
                        def avgCvss      = scanJson.average_cvss ?: 0
                        def trackers     = scanJson.trackers?.detected_trackers ?: 0

                        env.MOBSF_SECURITY_SCORE = "${securityScore}"
                        env.MOBSF_AVG_CVSS       = "${avgCvss}"
                        env.MOBSF_TRACKERS       = "${trackers}"

                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        echo "Security score : ${securityScore}/100"
                        echo "Average CVSS   : ${avgCvss}"
                        echo "Trackers       : ${trackers}"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    }
                }
            }
        }

        // ── Stage 6: Download MobSF PDF report ───────────────────────────
        stage('Download MobSF report') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'mobsf-api-key', variable: 'MOBSF_KEY')]) {
                        // Download JSON report
                        def jsonReport = sh(
                            script: """
                                curl -s -X POST \
                                  -H "X-Mobsf-Api-Key: \${MOBSF_KEY}" \
                                  -H "Content-Type: application/x-www-form-urlencoded" \
                                  --data-urlencode "hash=${env.MOBSF_HASH}" \
                                  ${env.MOBSF_HOST}/api/v1/report_json
                            """,
                            returnStdout: true
                        ).trim()

                        writeFile file: 'mobsf-report.json', text: jsonReport
                        archiveArtifacts artifacts: 'mobsf-report.json', allowEmptyArchive: true

                        // Download PDF report
                        sh """
                            curl -s -X POST \
                              -H "X-Mobsf-Api-Key: \${MOBSF_KEY}" \
                              -H "Content-Type: application/x-www-form-urlencoded" \
                              --data-urlencode "hash=${env.MOBSF_HASH}" \
                              -o mobsf-report.pdf \
                              ${env.MOBSF_HOST}/api/v1/download_pdf
                        """
                        archiveArtifacts artifacts: 'mobsf-report.pdf', allowEmptyArchive: true

                        echo "Reports downloaded and archived"
                    }
                }
            }
        }

        // ── Stage 7: Parse findings ───────────────────────────────────────
        stage('Parse security findings') {
            steps {
                script {
                    def reportJson = readJSON file: 'mobsf-report.json'

                    // Security score — use value captured in Stage 5 from scan response
                    // The report_json endpoint uses a different structure than the scan response
                    def score = 0
                    if (env.MOBSF_SECURITY_SCORE && env.MOBSF_SECURITY_SCORE != 'N/A') {
                        score = env.MOBSF_SECURITY_SCORE as Integer
                    } else {
                        // Fallback — try multiple paths used across MobSF versions
                        score = (reportJson.appsec?.security_score
                              ?: reportJson.appsec?.score
                              ?: reportJson.security_score
                              ?: 0) as Integer
                    }

                    // Count findings by severity
                    def high   = 0
                    def warning = 0
                    def info   = 0
                    def secure = 0

                    def findingsList = reportJson.appsec?.findings ?: []
                    for (def finding in findingsList) {
                        def findingSev = ''
                        if (finding instanceof Map) {
                            findingSev = (finding.get('severity') ?: '').toLowerCase()
                        }
                        if (findingSev == 'high')         high++
                        else if (findingSev == 'warning') warning++
                        else if (findingSev == 'info')    info++
                        else if (findingSev == 'secure')  secure++
                    }

                    // Manifest issues
                    def manifestIssues = 0
                    def manifestList = reportJson.manifest_analysis ?: []
                    for (def item in manifestList) {
                        def itemSev = ''
                        if (item instanceof Map) {
                            itemSev = (item.get('severity') ?: '').toLowerCase()
                        }
                        if (itemSev == 'high' || itemSev == 'warning') manifestIssues++
                    }

                    // Dangerous permissions
                    def dangerousPerms = 0
                    if (reportJson.permissions instanceof Map) {
                        reportJson.permissions.each { entry ->
                            def details = entry.value
                            if (details instanceof Map) {
                                def status = details.get('status') ?: ''
                                if (status.toLowerCase() == 'dangerous') dangerousPerms++
                            }
                        }
                    }

                    // Hardcoded secrets / URLs
                    def secrets = (reportJson.secrets?.size() ?: 0) as Integer

                    // Trackers
                    def trackers = (reportJson.trackers?.detected_trackers ?: 0) as Integer

                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "Security score     : ${score}/100"
                    echo "High findings      : ${high}"
                    echo "Warning findings   : ${warning}"
                    echo "Manifest issues    : ${manifestIssues}"
                    echo "Dangerous perms    : ${dangerousPerms}"
                    echo "Hardcoded secrets  : ${secrets}"
                    echo "Trackers detected  : ${trackers}"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

                    env.MOBSF_SCORE           = "${score}"
                    env.MOBSF_HIGH            = "${high}"
                    env.MOBSF_WARNING         = "${warning}"
                    env.MOBSF_INFO            = "${info}"
                    env.MOBSF_MANIFEST_ISSUES = "${manifestIssues}"
                    env.MOBSF_DANGEROUS_PERMS = "${dangerousPerms}"
                    env.MOBSF_SECRETS         = "${secrets}"
                    env.MOBSF_TRACKERS        = "${trackers}"

                    // Post GitLab comment with findings summary
                    postGitlabComment(buildMobSFComment(reportJson))

                    // Determine pipeline status
                    // Fail if score below 50 or high findings present or secrets found
                    if (score < 50 || high > 0 || secrets > 0) {
                        env.PIPELINE_FAILED = 'true'
                        def reasons = []
                        if (score < 50)  reasons << "Security score is ${score}/100 (minimum 50)"
                        if (high > 0)    reasons << "${high} HIGH severity findings"
                        if (secrets > 0) reasons << "${secrets} hardcoded secret(s) detected"
                        env.PIPELINE_FAIL_REASON = reasons.join(' | ')
                    }
                }
            }
        }

        // ── Stage 8: Generate mobile security report ──────────────────────
        stage('Generate mobile security report') {
            steps {
                script {
                    writeFile file: '/tmp/mobile-report-env.sh', text: """
export REPO_NAME="${env.REPO_NAME}"
export GITLAB_REPO_PATH="${env.GITLAB_REPO_PATH}"
export REPO_COMMIT="${env.REPO_COMMIT}"
export GIT_BRANCH="${env.GIT_BRANCH ?: 'main'}"
export BUILD_NUMBER="${env.BUILD_NUMBER}"
export BUILD_URL="${env.BUILD_URL}"
export PIPELINE_STATUS="${env.PIPELINE_FAILED == 'true' ? 'FAILED' : 'PASSED'}"
export WORKSPACE="${env.WORKSPACE}"
export APK_NAME="${env.APK_NAME}"
export APK_SIZE="${env.APK_SIZE}"
export MOBSF_HOST="${env.MOBSF_HOST}"
export MOBSF_HASH="${env.MOBSF_HASH}"
export MOBSF_SCORE="${env.MOBSF_SCORE ?: '0'}"
export MOBSF_HIGH="${env.MOBSF_HIGH ?: '0'}"
export MOBSF_WARNING="${env.MOBSF_WARNING ?: '0'}"
export MOBSF_INFO="${env.MOBSF_INFO ?: '0'}"
export MOBSF_MANIFEST_ISSUES="${env.MOBSF_MANIFEST_ISSUES ?: '0'}"
export MOBSF_DANGEROUS_PERMS="${env.MOBSF_DANGEROUS_PERMS ?: '0'}"
export MOBSF_SECRETS="${env.MOBSF_SECRETS ?: '0'}"
export MOBSF_TRACKERS="${env.MOBSF_TRACKERS ?: '0'}"
"""
                    writeFile file: '/tmp/mobile-report-reason.txt',
                              text: env.PIPELINE_FAIL_REASON ?: ''

                    sh '''
                        . /tmp/mobile-report-env.sh
                        export PIPELINE_FAIL_REASON=$(cat /tmp/mobile-report-reason.txt)
                        python3 /tmp/generate-mobile-report.py
                        rm -f /tmp/mobile-report-env.sh /tmp/mobile-report-reason.txt
                    '''

                    archiveArtifacts artifacts: 'mobile-security-report.html', allowEmptyArchive: true
                    echo "Mobile security report archived"
                }
            }
        }

        // ── Stage 9: Security Gate ────────────────────────────────────────
        stage('Security Gate') {
            steps {
                script {
                    if (env.PIPELINE_FAILED == 'true') {
                        error "Mobile security pipeline failed: ${env.PIPELINE_FAIL_REASON}"
                    }
                    echo "Security Gate passed — APK meets minimum security requirements"
                }
            }
        }
    }

    post {
        success {
            script {
                def msg = "### Mobile Security Pipeline\n\n" +
                          "**Status: PASSED** ✅\n\n" +
                          "**APK:** ${env.APK_NAME}\n\n" +
                          "**Security Score:** ${env.MOBSF_SCORE}/100\n\n" +
                          "**HIGH findings:** ${env.MOBSF_HIGH ?: 0}\n\n" +
                          "**Warnings:** ${env.MOBSF_WARNING ?: 0}\n\n" +
                          "**Dangerous permissions:** ${env.MOBSF_DANGEROUS_PERMS ?: 0}\n\n" +
                          "**Trackers detected:** ${env.MOBSF_TRACKERS ?: 0}\n\n" +
                          "[View full report in MobSF](${env.MOBSF_HOST}/static_analysis/?name=${env.MOBSF_FILE_NAME}&checksum=${env.MOBSF_HASH}&type=${env.MOBSF_SCAN_TYPE})"
                postGitlabComment(msg)
            }
            updateGitlabCommitStatus name: 'ci/jenkins-mobile', state: 'success'
        }
        failure {
            updateGitlabCommitStatus name: 'ci/jenkins-mobile', state: 'failed'
        }
    }
}

// ── Helper: build MobSF GitLab comment ───────────────────────────────────────
def buildMobSFComment(def reportJson) {
    def score    = (env.MOBSF_SCORE   ?: '0').toInteger()
    def high     = (env.MOBSF_HIGH    ?: '0').toInteger()
    def warning  = (env.MOBSF_WARNING ?: '0').toInteger()
    def secrets  = (env.MOBSF_SECRETS ?: '0').toInteger()
    def perms    = (env.MOBSF_DANGEROUS_PERMS ?: '0').toInteger()
    def trackers = (env.MOBSF_TRACKERS ?: '0').toInteger()

    def status = (score < 50 || high > 0 || secrets > 0) ? 'FAILED' : 'WARNING'
    if (score >= 50 && high == 0 && secrets == 0 && warning == 0) status = 'PASSED'

    def message = "### MobSF Static Analysis — ${env.APK_NAME}\n\n"
    message += "**Status: ${status}**\n\n"
    message += "| Metric | Value |\n"
    message += "|--------|-------|\n"
    message += "| Security Score | **${score}/100** |\n"
    message += "| HIGH findings | **${high}** |\n"
    message += "| Warnings | **${warning}** |\n"
    message += "| Dangerous permissions | **${perms}** |\n"
    message += "| Hardcoded secrets | **${secrets}** |\n"
    message += "| Trackers detected | **${trackers}** |\n\n"

    // Top HIGH findings
    def highFindings = reportJson.appsec?.findings?.findAll {
        it.severity?.toLowerCase() == 'high'
    } ?: []

    if (highFindings) {
        message += "#### HIGH severity findings\n\n"
        highFindings.take(5).each { f ->
            def title = f.title ?: f.issue ?: 'Security issue'
            message += "- **${title}**\n"
        }
        if (highFindings.size() > 5) {
            message += "- _...and ${highFindings.size() - 5} more_\n"
        }
        message += "\n"
    }

    // Dangerous permissions
    def dangerousPermList = []
    if (reportJson.permissions instanceof Map) {
        reportJson.permissions.each { entry ->
            def details = entry.value
            if (details instanceof Map) {
                def permStatus = details.get('status') ?: ''
                if (permStatus.toLowerCase() == 'dangerous') {
                    dangerousPermList << entry.key
                }
            }
        }
    }
    if (dangerousPermList) {
        message += "#### Dangerous permissions\n\n"
        dangerousPermList.take(5).each { p ->
            message += "- " + "`" + p + "`" + "\n"
        }
        if (dangerousPermList.size() > 5) {
            message += "- _...and ${dangerousPermList.size() - 5} more_\n"
        }
        message += "\n"
    }

    message += "---\n"
    message += "[View full MobSF report](${env.MOBSF_HOST}/static_analysis/?name=${env.MOBSF_FILE_NAME}&checksum=${env.MOBSF_HASH}&type=${env.MOBSF_SCAN_TYPE})\n"
    message += "_See mobile-security-report.html in Jenkins artifacts for summary report._"

    return message
}

// ── Helper: post comment to GitLab commit ────────────────────────────────────
def postGitlabComment(String message) {
    def gitlabHost = env.GITLAB_HOST
    def projectId  = env.GITLAB_PROJECT_ID
    def commitSha  = env.REPO_COMMIT ?: env.GIT_COMMIT

    if (!projectId || !commitSha) {
        echo "Skipping GitLab comment — project ID or commit SHA not available"
        return
    }

    withCredentials([string(credentialsId: 'gitlab-api-token', variable: 'GL_TOKEN')]) {
        writeFile file: 'mobile-comment-body.txt', text: message
        sh """
            python3 -c "
import json
with open('mobile-comment-body.txt', 'r') as f:
    note = f.read()
payload = json.dumps({'note': note})
with open('mobile-gitlab-comment.json', 'w') as f:
    f.write(payload)
"
            curl -s --request POST \\
              --header "PRIVATE-TOKEN: \$GL_TOKEN" \\
              --header "Content-Type: application/json" \\
              --data @mobile-gitlab-comment.json \\
              "${gitlabHost}/api/v4/projects/${projectId}/repository/commits/${commitSha}/comments"
            rm -f mobile-gitlab-comment.json mobile-comment-body.txt
        """
    }
}
