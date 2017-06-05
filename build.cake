#addin "nuget:?package=NuGet.Core"
#addin "Cake.FileHelpers"
#addin "Cake.Incubator"
#addin "Cake.ExtendedNuGet"
#tool "nuget:?package=xunit.runner.console"
#tool "nuget:?package=vswhere"

var target        = Argument("target", "Default");
var configuration = Argument("configuration", "Release");
var buildNumber   = Argument("buildnumber", "0");
var buildDir      = Directory("./artifacts");
var solution      = "./src/Dks.SimpleToken.sln";

var corePackProjects = new []
{
	"./src/Dks.SimpleToken.Core/*.csproj",
	"./src/Dks.SimpleToken.Serializers.Protobuf/*.csproj",
	"./src/Dks.SimpleToken.Validation.MVC6/*.csproj",
	"./src/Dks.SimpleToken.Validation.WebAPI/*.csproj", 
	"./src/Dks.SimpleToken.Validation.MVC5/*.csproj", 
	"./src/Dks.SimpleToken.SystemWeb/*.csproj"
};

var coreTestProjects = new []
{
	"./src/Dks.SimpleToken.Tests/*.csproj", 
	"./src/Dks.SimpleToken.MVC6.Tests/*.csproj"	
};

var frameworkTestProjects = new []
{
	"./src/Dks.SimpleToken.SystemWeb.Tests/bin/Release/*.Tests.dll", 
	"./src/Dks.SimpleToken.MVC5.Tests/bin/Release/*.Tests.dll", 
	"./src/Dks.SimpleToken.WebAPI.Tests/bin/Release/*.Tests.dll"
};

Task("Clean")
    .Does(() =>
{
    CleanDirectory(buildDir);
});

Task("RestorePackages")
    .IsDependentOn("Clean")
    .Does(() =>
{
    NuGetRestore(solution);
});

Task("Build")
    .IsDependentOn("RestorePackages")
    .Does(() =>
{
    MSBuild(solution, settings => settings
        .SetConfiguration(configuration)
        .SetVerbosity(Verbosity.Minimal)
        .UseToolVersion(MSBuildToolVersion.VS2017)
    );
});

Task("RunCoreTests")
	.Does(() => 
{
	var projects = GetFiles(coreTestProjects);

	var settings = new DotNetCoreTestSettings
    {
        Configuration = configuration,
	    NoBuild = true
    };
	
	Information("Executing xUnit tests on projects:");
	foreach(var p in projects)
		Information(p.FullPath);

	foreach(var project in projects)
	{
		DotNetCoreTest(project.FullPath, settings);
	}
});

Task("RunTests")
	.IsDependentOn("Build")
	.IsDependentOn("RunCoreTests");

Task("Package")
	.IsDependentOn("Build")
	.Does(() =>
{
	var projects = GetFiles(corePackProjects);

	foreach(var project in projects)
	{
		PackageCoreProject(project.FullPath);
	}

});

private void PackageCoreProject(string projectPath)
{
    var settings = new DotNetCorePackSettings
        {
            OutputDirectory = buildDir,
			Configuration = configuration,
            NoBuild = true
        };

    DotNetCorePack(projectPath, settings);    
}  

Task("Default")
    .IsDependentOn("RunTests")
    .IsDependentOn("Package");

RunTarget(target);