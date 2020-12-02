name := "cryptoutils"

organization := "com.github.karasiq"

version := "2.0.0-SNAPSHOT"

isSnapshot := version.value.endsWith("SNAPSHOT")

scalaVersion := "2.12.12"

crossScalaVersions := Seq("2.11.12", "2.12.12")

resolvers += "softprops-maven" at "https://dl.bintray.com/content/softprops/maven"

libraryDependencies ++= Seq(
  "commons-io" % "commons-io" % "2.5",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.67" % "provided",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.67" % "provided",
  "org.bouncycastle" % "bctls-jdk15on" % "1.67" % "provided",
  "com.typesafe" % "config" % "1.3.1",
  "org.scalatest" %% "scalatest" % "3.0.4" % "test"
)

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

publishArtifact in Test := false

pomIncludeRepository := { _ ⇒ false }

licenses := Seq("The MIT License" → url("https://opensource.org/licenses/MIT"))

homepage := Some(url(s"https://github.com/Karasiq/${name.value}"))

pomExtra := <scm>
  <url>git@github.com:Karasiq/{name.value}.git</url>
  <connection>scm:git:git@github.com:Karasiq/{name.value}.git</connection>
</scm>
  <developers>
    <developer>
      <id>karasiq</id>
      <name>Piston Karasiq</name>
      <url>https://github.com/Karasiq</url>
    </developer>
  </developers>
