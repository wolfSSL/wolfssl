# cmake -P script: stop the build of an SBOM target that cannot run.
# sbom.cmake uses it when python3, or pyspdxtools for VALIDATE, was not
# found at configure time. Configure succeeds, and the build of the target
# gives the reason.

message(FATAL_ERROR "sbom: ${WOLFSSL_COMPLIANCE_TOOLING_SBOM_ERROR}")
