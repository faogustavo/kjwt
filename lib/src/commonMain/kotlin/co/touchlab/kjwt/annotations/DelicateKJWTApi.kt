package co.touchlab.kjwt.annotations

/**
 * APIs annotated as internal KJWT API are not meant for usage in client code; there are no
 * guarantees about binary nor source compatibility, and the behavior can change at any time.
 * **Avoid the usage** of these APIs in client code!
 */
@Target(
    allowedTargets = [
        AnnotationTarget.CLASS,
        AnnotationTarget.CONSTRUCTOR,
        AnnotationTarget.FIELD,
        AnnotationTarget.FUNCTION,
        AnnotationTarget.PROPERTY,
        AnnotationTarget.PROPERTY_GETTER,
        AnnotationTarget.PROPERTY_SETTER,
        AnnotationTarget.TYPEALIAS,
        AnnotationTarget.VALUE_PARAMETER,
    ],
)
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "API marked with this annotation should be used only when you know what you are doing. " +
        "Avoid usage of such declarations as much as possible. " +
        "They are provided mostly for backward compatibility with older services that require them.",
)
public annotation class DelicateKJWTApi
