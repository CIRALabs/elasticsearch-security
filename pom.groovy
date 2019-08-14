project {
  modelVersion '4.0.0'
  groupId 'ca.ciralabs'
  artifactId 'elastic-auth-plugin'
  version '2019.08.14'
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
      version '7.3.0'
      scope 'provided'
    }
    dependency {
      groupId 'com.unboundid'
      artifactId 'unboundid-ldapsdk'
      version '4.0.6'
    }
    dependency {
      groupId 'io.jsonwebtoken'
      artifactId 'jjwt-api'
      version '0.10.5'
    }
    dependency {
      groupId 'io.jsonwebtoken'
      artifactId 'jjwt-impl'
      version '0.10.5'
      scope 'runtime'
    }
    dependency {
      groupId 'io.jsonwebtoken'
      artifactId 'jjwt-jackson'
      version '0.10.5'
      scope 'runtime'
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
