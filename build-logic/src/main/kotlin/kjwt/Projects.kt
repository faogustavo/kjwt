package kjwt

object Projects {
    private enum class Type { Library, Misc }

    private val allProjects = mapOf(
        ":kjwt" to Type.Library,
    )

    val allLibraries: Set<String> = allProjects.filter { it.value == Type.Library }.keys
}