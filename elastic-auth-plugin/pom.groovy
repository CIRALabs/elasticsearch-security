project {
  modelVersion '4.0.0'
  groupId 'ca.ciralabs'
  artifactId 'elastic-auth-plugin'
  version '1.0-SNAPSHOT'
  description 'Provides authentication support for Elasticsearch'
  properties {
    'project.build.sourceEncoding' 'UTF-8'
    'maven.compiler.source' '1.8'
    'maven.compiler.target' '1.8'
  }
  dependencies {
    dependency {
      groupId 'junit'
      artifactId 'junit'
      version '4.11'
      scope 'test'
    }
    dependency {
      groupId 'org.elasticsearch'
      artifactId 'elasticsearch'
      version '6.3.0'
      scope 'provided'
    }
    dependency {
      groupId 'com.unboundid'
      artifactId 'unboundid-ldapsdk'
      version '4.0.6'
    }
    dependency {
      groupId 'com.auth0'
      artifactId 'java-jwt'
      version '3.4.0'
      exclusions {
        exclusion {
          groupId 'com.fasterxml.jackson.core'
          artifactId 'jackson-core'
        }
      }
    }
  }
  build {
    resources {
      resource {
        directory 'src/main/resources'
        filtering false
        excludes '*.properties'
      }
    }
    plugins {
      plugin {
        groupId 'org.apache.maven.plugins'
        artifactId 'maven-assembly-plugin'
        version '2.6'
        configuration {
          appendAssemblyId false
          outputDirectory '${project.build.directory}/releases/'
          descriptors '${basedir}/src/main/assemblies/plugin.xml'
        }
        executions {
          execution {
            phase 'package'
            goals {
              goal 'single'
            }
          }
        }
      }
    }
  }
}