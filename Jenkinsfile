node('docker') {
     stage('clean ws') {
     deleteDir()
     }
     stage('checkout') {
        checkout scm
     }
     stage('docker-pull') {
        sh 'docker pull fbelzunc/ad-build-container'
     }
     stage('maven') {
        sh 'docker run --add-host=samdom.example.com:127.0.0.1 -v /var/lib/docker --privileged --dns=127.0.0.1 --dns=8.8.8.8 -v $WORKSPACE:/project  fbelzunc/ad-build-container-with-docker-fixtures'
     }
     stage('surefire-report') {
        junit 'target/surefire-reports/*.xml'
     }
     stage('clean ws') {
     cleanWs()
     }
}