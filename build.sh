#!/bin/bash
cd $(dirname $0)
set -e

# 从 pom.xml 提取项目本身的 artifactId 和 version（跳过 parent）
ARTIFACT_ID=$(sed -n '/<\/parent>/,/<\/project>/p' pom.xml | grep -m1 '<artifactId>' | sed 's/.*<artifactId>\([^<]*\)<\/artifactId>.*/\1/')
PROJECT_NAME="${ARTIFACT_ID}"


MVN_OPTS="-Denforcer.skip=true -DskipTests"
print_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build        Build the plugin (default)"
    echo "  clean        Clean build artifacts"
    echo "  package      Build and package the plugin"
    echo "  deploy       Build and deploy to local Maven repo"
    echo "  help         Show this help message"
    echo ""
    echo "Options:"
    echo "  -v, --verbose   Enable verbose output"
    echo "  -d, --debug     Enable debug mode"
}

clean() {
    echo "Cleaning build artifacts..."
    mvn clean
}

build() {
    echo "Building $PROJECT_NAME..."
    mvn compile $MVN_OPTS ${VERBOSE:+"-X"}
}

package() {
    echo "Packaging $PROJECT_NAME..."
    mvn package $MVN_OPTS ${VERBOSE:+"-X"}
    HPI_FILE=$(find target -name "${PROJECT_NAME}*.hpi" | head -1)
    if [ -f "$HPI_FILE" ]; then
        echo ""
        echo "✅ Build successful!"
        echo "📦 Plugin file: $HPI_FILE"
        echo "📁 File size: $(du -h "$HPI_FILE" | awk '{print $1}')"
    else
        echo "❌ Build failed - HPI file $HPI_FILE not found"
        exit 1
    fi
}

deploy() {
    echo "Deploying $PROJECT_NAME to local Maven repository..."
    mvn deploy $MVN_OPTS -DaltDeploymentRepository=local::default::file://$HOME/.m2/repository
}

VERBOSE=0

if [ $# -eq 0 ]; then
    package
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        build)
            build
            shift
            ;;
        clean)
            clean
            shift
            ;;
        package)
            package
            shift
            ;;
        deploy)
            deploy
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -d|--debug)
            set -x
            shift
            ;;
        help|--help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown command: $1"
            print_usage
            exit 1
            ;;
    esac
done