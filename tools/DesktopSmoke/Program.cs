using SupertonicVox.Desktop;

await using var viewModel = new MainWindowViewModel();
await viewModel.InitializeAsync();
Console.WriteLine($"status={viewModel.Status}");
Console.WriteLine($"recommendation={viewModel.RecommendationTitle}");
Console.WriteLine($"recommendation_summary={viewModel.RecommendationSummary}");
Console.WriteLine($"security_summary={viewModel.SecuritySummary}");
Console.WriteLine($"synthesis_status={viewModel.SynthesisStatus}");
Console.WriteLine($"engine_count={viewModel.EngineCards.Count}");
return viewModel.Status == "오프라인 분석 완료" &&
       viewModel.SynthesisStatus.StartsWith("✓", StringComparison.Ordinal)
    ? 0
    : 1;
