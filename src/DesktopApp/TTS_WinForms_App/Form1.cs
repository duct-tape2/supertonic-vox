using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Media;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using HtmlAgilityPack;
using Newtonsoft.Json.Linq;
using TTS_WinForms_App.Services;

namespace TTS_WinForms_App;

public class Form1 : Form
{
	private static string InstallRoot => AppContext.BaseDirectory;

	private static string InternalRoot => Path.Combine(InstallRoot, "_internal");

	private enum TtsEngineKind
	{
		Supertonic,
		VoxCpm2,
		HiggsAudioV3
	}

	public class VoiceItem
	{
		public string VoiceId { get; set; }

		public string VoiceName { get; set; }

		public VoiceItem(string id, string name)
		{
			VoiceId = id;
			VoiceName = name;
		}

		public override string ToString()
		{
			return VoiceName;
		}
	}

	private class WavData
	{
		public int AudioFormat { get; set; }

		public int SampleRate { get; set; }

		public int Channels { get; set; }

		public int BitsPerSample { get; set; }

		public byte[] Data { get; set; }
	}

	private class PronunciationRule
	{
		public string From { get; set; }

		public string To { get; set; }

		public string Note { get; set; }

		public PronunciationRule(string from, string to, string note)
		{
			From = from;
			To = to;
			Note = note;
		}
	}

	private sealed record VoxGenerationSnapshot(
		string Title,
		string Text,
		string OutputDirectory,
		string ProfileId,
		string? ReferencePath,
		int InferenceSteps,
		double SpeedFactor,
		double VolumeFactor,
		double SilenceSeconds,
		int Seed);

	private sealed class VoxChunkTimeoutException : TimeoutException
	{
		public VoxChunkTimeoutException(int chunkNumber, int chunkCount, Exception innerException)
			: base($"VoxCPM2 조각 {chunkNumber}/{chunkCount} 생성이 30분 제한 시간을 초과했습니다. 앱이 시작한 Vox 서버를 종료했으며 불완전한 WAV는 삭제했습니다. 다시 시도해주세요.", innerException)
		{
		}
	}

	private SoundPlayer soundPlayer;

	private const string EngineSupertonic = "Supertonic Local";

	private const string EngineVoxCpm2 = "VoxCPM2 Local";

	private const string VoxModelRevision = "bffb3df5a29440629464e5e839f4d214c8714c3d";

	private const long VoxModelSize = 4580080592L;

	private const long VoxAudioVaeSize = 376951122L;

	private const string SampleCacheVersion = "tone10-court";

	private const string EngineHiggs = "Higgs Audio v3 Local (CUDA/CPU Q8)";

	private const long HiggsModelSize = 5095354048L;

	private const string HiggsSampleCacheSchema = "higgs-sample-v6-continuity-anchor";

	private const string HiggsVoiceAnchorSchema = "higgs-voice-anchor-v1";

	private const string HiggsSampleText = "안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.";

	private const int HiggsChunkMaxLength = 200;

	private const int HiggsMaxTokensRetryCap = 4096;

	private const ulong HiggsMinimumAvailableCommitBytes = 12884901888uL;

	private static readonly IReadOnlyDictionary<string, (long Size, string Sha256)> SupertonicModelIntegrity =
		new Dictionary<string, (long, string)>(StringComparer.OrdinalIgnoreCase)
		{
			["onnx/duration_predictor.onnx"] = (3700147L, "c3eb91414d5ff8a7a239b7fe9e34e7e2bf8a8140d8375ffb14718b1c639325db"),
			["onnx/text_encoder.onnx"] = (36416150L, "c7befd5ea8c3119769e8a6c1486c4edc6a3bc8365c67621c881bbb774b9902ff"),
			["onnx/tts.json"] = (8564L, "cf1a393b4f46c16d5af623228566d62658c7ef18bb524549c5ad70c583675121"),
			["onnx/unicode_indexer.json"] = (277676L, "9bf7346e43883a81f8645c81224f786d43c5b57f3641f6e7671a7d6c493cb24f"),
			["onnx/vector_estimator.onnx"] = (256534781L, "883ac868ea0275ef0e991524dc64f16b3c0376efd7c320af6b53f5b780d7c61c"),
			["onnx/vocoder.onnx"] = (101424195L, "085de76dd8e8d5836d6ca66826601f615939218f90e519f70ee8a36ed2a4c4ba"),
			["voice_styles/F1.json"] = (292046L, "bbdec6ee00231c2c742ad05483df5334cab3b52fda3ba38e6a07059c4563dbc2"),
			["voice_styles/F2.json"] = (292423L, "7c722c6a72707b1a77f035d67f0d1351ba187738e06f7683e8c72b1df3477fc6"),
			["voice_styles/F3.json"] = (290794L, "12f6ef2573baa2defa1128069cb59f203e3ab67c92af77b42df8a0e3a2f7c6ab"),
			["voice_styles/F4.json"] = (291808L, "c2fa764c1225a76dfc3e2c73e8aa4f70d9ee48793860eb34c295fff01c2e032b"),
			["voice_styles/F5.json"] = (291479L, "45966e73316415626cf41a7d1c6f3b4c70dbc1ba2bee5c1978ef0ce33244fc8d"),
			["voice_styles/M1.json"] = (291748L, "e35604687f5d23694b8e91593a93eec0e4eca6c0b02bb8ed69139ab2ea6b0a5b"),
			["voice_styles/M2.json"] = (292055L, "b76cbf62bac707c710cf0ae5aba5e31eea1a6339a9734bfae33ab98499534a50"),
			["voice_styles/M3.json"] = (290198L, "ea1ac35ccb91b0d7ecad533a2fbd0eec10c91513d8951e3b25fbba99954e159b"),
			["voice_styles/M4.json"] = (291522L, "ca8eefad4fcd989c9379032ff3e50738adc547eeb5e221b82593a6d7b3bac303"),
			["voice_styles/M5.json"] = (291469L, "dd22b92740314321f8ae11c5e87f8dd60d060f15dd3a632b5adf77f471f77af2")
		};

	private const string SupertonicModelRevision = "0d6a2bed57a1c6ec4f7acf77d688c62337655dd1db2a5582b2b2d55c17f5efae";

	private const string TonePresetCourtPleading = "법정 변론";

	private string settingsFilePath;

	private string pronunciationOverridesPath;

	private string savedAudioPath;

	private string lastGeneratedAudioPath;

	private Process supertonicProcess;

	private readonly object supertonicLogLock = new object();

	private int supertonicPort;

	private string supertonicSessionToken = "";

	private string supertonicSessionId = "";

	private Process voxProcess;

	private readonly object voxLogLock = new object();

	private int voxPort;

	private string voxSessionToken = "";

	private string voxSessionId = "";

	private Mutex voxModelMutex;

	private CancellationTokenSource generationCancellation;

	private bool generationInProgress;

	private bool loadingSettings;

	private bool suppressEngineSelectionChanged;

	private TtsEngineKind lastSelectedEngine = TtsEngineKind.Supertonic;

	private string cachedSupertonicVoice = "M1";

	private string cachedVoxVoice = "vox_news_f";

	private int cachedSupertonicSpeed = 105;

	private int cachedVoxSpeed = 100;

	private string cachedSupertonicQuality = "균형";

	private string cachedVoxQuality = "고품질";

	private int cachedSupertonicVolume = 100;

	private int cachedVoxVolume = 100;

	private int cachedSupertonicPause = 25;

	private int cachedVoxPause = 25;

	private string cachedSupertonicTone = "기본";

	private string voxReferenceId = "";

	private string voxReferencePath = "";

	private string voxReferenceDisplayName = "";

	private Process higgsProcess;

	private readonly object higgsLogLock = new object();

	private int higgsPort;

	private bool higgsMemoryRecoveryAttempted;

	private bool higgsUseLowMemoryReference;

	private bool higgsForceCpuForSession;

	private bool? higgsCudaAvailable;

	private string higgsActiveBackend = "cpu";

	private string cachedHiggsVoice = "higgs_default";

	private int cachedHiggsSpeed = 100;

	private string cachedHiggsQuality = "고품질";

	private int cachedHiggsVolume = 100;

	private int cachedHiggsPause = 25;

	private string cachedHiggsTone = "기본";

	private int cachedHiggsSeed = 42;

	private const int MaxChunkLength = 1200;

	private const int VoxMaxChunkLength = 220;

	private Label labelTitle;

	private TextBox textBoxTitle;

	private Label labelContent;

	private RichTextBox richTextBoxContent;

	private Label labelVoice;

	private ComboBox comboBoxVoice;

	private Label labelGuide;

	private RichTextBox richTextBoxGuide;

	private Label labelSaveDirectory;

	private TextBox textBoxSaveDirectory;

	private Button buttonGenerateAudio;

	private Button buttonPlaySample;

	private Button buttonSaveSettings;

	private Button buttonSelectFolder;

	private Button buttonOpenFolder;

	private Button buttonLoadFile;

	private Button buttonOpenBlog;

	private ProgressBar progressBarTts;

	private Label labelProgressStatus;

	private Label labelEngine;

	private ComboBox comboBoxEngine;

	private Label labelSpeed;

	private TrackBar trackBarSpeed;

	private Label labelSpeedValue;

	private Label labelQuality;

	private ComboBox comboBoxQuality;

	private Label labelTonePreset;

	private ComboBox comboBoxTonePreset;

	private Label labelPitch;

	private TrackBar trackBarPitch;

	private Label labelPitchValue;

	private Label labelVolume;

	private TrackBar trackBarVolume;

	private Label labelVolumeValue;

	private Label labelPause;

	private TrackBar trackBarPause;

	private Label labelPauseValue;

	private Button buttonPlayGenerated;

	private Button buttonStopGenerated;

	private Label labelModelStatus;

	private Button buttonOpenModelFolder;

	private Button buttonOpenLog;

	private Panel panelVoxReference;

	private Label labelVoxReferenceStatus;

	private Label labelVoxReferenceNotice;

	private Button buttonSelectReferenceWav;

	private Button buttonPlayReferenceWav;

	private Button buttonClearReferenceWav;

	private Button buttonPreviewPronunciation;

	private CheckBox checkBoxSibilantRescue;

	private ComboBox comboBoxSibilantMode;

	private Button buttonSibilantDebug;

	private bool sampleWarmupRunning;

	private int requestedSampleWarmupSpeed = -1;

	private int requestedSampleWarmupSteps = -1;

	private int requestedSampleWarmupPitch = 999;

	private int requestedSampleWarmupVolume = -1;

	private int requestedSampleWarmupPause = -1;

	private bool applyingTonePreset;

	private readonly string[] supertonicSampleVoices = new string[10] { "M1", "M2", "M3", "M4", "M5", "F1", "F2", "F3", "F4", "F5" };

	public Form1()
	{
		Directory.CreateDirectory(InternalRoot);
		InitializeComponent();
		InitializeCustomComponents();
		LoadSettings();
		LoadSavedText();
		LoadEngineGuide();
		NormalizeGuideText();
		base.FormClosing += Form1_FormClosing;
		QueueSupertonicSampleWarmup();
	}

	private void InitializeCustomComponents()
	{
		soundPlayer = new SoundPlayer();
		settingsFilePath = Path.Combine(InternalRoot, "settings.json");
		pronunciationOverridesPath = Path.Combine(InternalRoot, "pronunciation_overrides.json");
		savedAudioPath = GetDefaultAudioPath();
		Directory.CreateDirectory(savedAudioPath);
		textBoxSaveDirectory.Text = savedAudioPath;
		base.ClientSize = new Size(1250, 780);
		base.MinimumSize = new Size(900, 620);
		labelEngine = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Location = new Point(529, 11),
			Name = "labelEngine",
			Text = "엔진 선택"
		};
		comboBoxEngine = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Location = new Point(529, 33),
			Name = "comboBoxEngine",
			Size = new Size(288, 23)
		};
		comboBoxEngine.Items.Add("Supertonic Local");
		comboBoxEngine.Items.Add("VoxCPM2 Local");
		comboBoxEngine.Items.Add("Higgs Audio v3 Local (CUDA/CPU Q8)");
		comboBoxEngine.SelectedIndex = 0;
		comboBoxEngine.SelectedIndexChanged += comboBoxEngine_SelectedIndexChanged;
		labelVoice.Location = new Point(529, 121);
		comboBoxVoice.Location = new Point(529, 143);
		buttonPlaySample.Location = new Point(728, 143);
		labelSpeed = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Location = new Point(529, 176),
			Name = "labelSpeed",
			Text = "배속"
		};
		trackBarSpeed = new TrackBar
		{
			Location = new Point(529, 197),
			Minimum = 80,
			Maximum = 150,
			TickFrequency = 10,
			SmallChange = 5,
			LargeChange = 10,
			Value = 105,
			Size = new Size(220, 45)
		};
		trackBarSpeed.ValueChanged += trackBarSpeed_ValueChanged;
		labelSpeedValue = new Label
		{
			AutoSize = true,
			Location = new Point(760, 207),
			Name = "labelSpeedValue",
			Text = "1.05x"
		};
		labelQuality = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Location = new Point(529, 242),
			Name = "labelQuality",
			Text = "품질 모드"
		};
		comboBoxQuality = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Location = new Point(529, 264),
			Name = "comboBoxQuality",
			Size = new Size(288, 23)
		};
		comboBoxQuality.Items.Add("빠른 생성");
		comboBoxQuality.Items.Add("균형");
		comboBoxQuality.Items.Add("고품질");
		comboBoxQuality.SelectedIndex = 2;
		comboBoxQuality.SelectedIndexChanged += comboBoxQuality_SelectedIndexChanged;
		labelTonePreset = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Name = "labelTonePreset",
			Text = "감정/톤"
		};
		comboBoxTonePreset = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Name = "comboBoxTonePreset",
			Size = new Size(288, 23)
		};
		comboBoxTonePreset.Items.AddRange(new object[10] { "기본", "밝고 활기차게", "차분하고 부드럽게", "힘있고 또렷하게", TonePresetCourtPleading, "낮고 진지하게", "부드러운 속삭임", "긴장감 있게", "캐릭터 밝게", "사용자 설정" });
		comboBoxTonePreset.SelectedIndex = 0;
		comboBoxTonePreset.SelectedIndexChanged += comboBoxTonePreset_SelectedIndexChanged;
		labelPitch = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Name = "labelPitch",
			Text = "피치"
		};
		trackBarPitch = new TrackBar
		{
			Minimum = 0,
			Maximum = 0,
			TickFrequency = 1,
			SmallChange = 1,
			LargeChange = 1,
			Value = 0,
			Enabled = false,
			Size = new Size(220, 45)
		};
		trackBarPitch.ValueChanged += voiceEffect_ValueChanged;
		labelPitchValue = new Label
		{
			AutoSize = true,
			Name = "labelPitchValue",
			Text = "자연 고정"
		};
		labelVolume = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Name = "labelVolume",
			Text = "볼륨"
		};
		trackBarVolume = new TrackBar
		{
			Minimum = 70,
			Maximum = 130,
			TickFrequency = 10,
			SmallChange = 5,
			LargeChange = 10,
			Value = 100,
			Size = new Size(220, 45)
		};
		trackBarVolume.ValueChanged += voiceEffect_ValueChanged;
		labelVolumeValue = new Label
		{
			AutoSize = true,
			Name = "labelVolumeValue",
			Text = "100%"
		};
		labelPause = new Label
		{
			AutoSize = true,
			Font = labelVoice.Font,
			Name = "labelPause",
			Text = "쉼"
		};
		trackBarPause = new TrackBar
		{
			Minimum = 10,
			Maximum = 60,
			TickFrequency = 10,
			SmallChange = 5,
			LargeChange = 10,
			Value = 25,
			Size = new Size(220, 45)
		};
		trackBarPause.ValueChanged += voiceEffect_ValueChanged;
		labelPauseValue = new Label
		{
			AutoSize = true,
			Name = "labelPauseValue",
			Text = "0.25s"
		};
		labelGuide.Location = new Point(529, 296);
		richTextBoxGuide.Location = new Point(529, 318);
		richTextBoxGuide.Size = new Size(288, 125);
		labelSaveDirectory.Location = new Point(529, 450);
		textBoxSaveDirectory.Location = new Point(529, 472);
		buttonSelectFolder.Location = new Point(760, 471);
		buttonOpenFolder.Location = new Point(791, 471);
		buttonSaveSettings.Location = new Point(529, 508);
		buttonGenerateAudio.Location = new Point(12, 436);
		buttonGenerateAudio.Size = new Size(323, 50);
		buttonPlayGenerated = new Button
		{
			Enabled = false,
			Font = buttonGenerateAudio.Font,
			Location = new Point(341, 436),
			Name = "buttonPlayGenerated",
			Size = new Size(82, 50),
			Text = "재생",
			UseVisualStyleBackColor = true
		};
		buttonPlayGenerated.Click += buttonPlayGenerated_Click;
		buttonStopGenerated = new Button
		{
			Enabled = false,
			Font = buttonGenerateAudio.Font,
			Location = new Point(429, 436),
			Name = "buttonStopGenerated",
			Size = new Size(82, 50),
			Text = "정지",
			UseVisualStyleBackColor = true
		};
		buttonStopGenerated.Click += buttonStopGenerated_Click;
		progressBarTts.Location = new Point(12, 494);
		progressBarTts.Size = new Size(499, 25);
		labelProgressStatus.Location = new Point(12, 525);
		base.Controls.Add(labelEngine);
		base.Controls.Add(comboBoxEngine);
		base.Controls.Add(labelSpeed);
		base.Controls.Add(trackBarSpeed);
		base.Controls.Add(labelSpeedValue);
		base.Controls.Add(labelQuality);
		base.Controls.Add(comboBoxQuality);
		base.Controls.Add(buttonPlayGenerated);
		base.Controls.Add(buttonStopGenerated);
		BuildModernLayout();
		LoadVoiceOptionsForEngine();
		UpdateEngineUiVisibility();
	}


	private void BuildModernLayout()
	{
		SuspendLayout();
		Text = "Supertonic + VoxCPM2";
		Font = new Font("맑은 고딕", 9f, FontStyle.Regular, GraphicsUnit.Point, 129);
		BackColor = Color.FromArgb(245, 247, 251);
		base.ClientSize = new Size(1440, 1280);
		MinimumSize = new Size(1180, 760);
		base.WindowState = FormWindowState.Normal;
		base.StartPosition = FormStartPosition.CenterScreen;
		base.Controls.Clear();
		labelTitle.Text = "제목 (파일명)";
		labelContent.Text = "변환할 텍스트";
		labelVoice.Text = "음성 선택";
		labelSpeed.Text = "배속";
		labelQuality.Text = "품질 모드";
		labelTonePreset.Text = "감정/톤";
		labelPitch.Text = "피치";
		labelVolume.Text = "볼륨";
		labelPause.Text = "쉼";
		labelSaveDirectory.Text = "저장 폴더";
		buttonLoadFile.Text = "파일 불러오기";
		buttonPlaySample.Text = "샘플";
		buttonSelectFolder.Text = "...";
		buttonOpenFolder.Text = "열기";
		buttonSaveSettings.Text = "설정 저장";
		buttonOpenBlog.Text = "개발자 바로가기";
		buttonGenerateAudio.Text = "음성 생성";
		buttonPlayGenerated.Text = "재생";
		buttonStopGenerated.Text = "정지";
		labelModelStatus = new Label
		{
			AutoSize = false,
			Dock = DockStyle.Fill,
			ForeColor = Color.FromArgb(20, 115, 65),
			TextAlign = ContentAlignment.MiddleLeft
		};
		buttonOpenModelFolder = new Button
		{
			Text = "모델 폴더",
			Height = 30,
			AutoSize = true
		};
		buttonOpenModelFolder.Click += buttonOpenModelFolder_Click;
		buttonOpenLog = new Button
		{
			Text = "로그",
			Height = 30,
			AutoSize = true
		};
		buttonOpenLog.Click += buttonOpenLog_Click;
		Control[] array = new Control[6] { textBoxTitle, comboBoxEngine, comboBoxVoice, comboBoxQuality, comboBoxTonePreset, textBoxSaveDirectory };
		foreach (Control obj in array)
		{
			obj.Font = Font;
			obj.Margin = new Padding(0, 4, 0, 8);
			obj.Height = 30;
		}
		richTextBoxContent.Font = new Font("맑은 고딕", 10f, FontStyle.Regular, GraphicsUnit.Point, 129);
		richTextBoxContent.BorderStyle = BorderStyle.FixedSingle;
		richTextBoxContent.Dock = DockStyle.Fill;
		richTextBoxGuide.Font = Font;
		richTextBoxGuide.BorderStyle = BorderStyle.FixedSingle;
		richTextBoxGuide.Height = 92;
		comboBoxEngine.Width = 380;
		comboBoxVoice.Width = 280;
		comboBoxQuality.Width = 380;
		comboBoxTonePreset.Width = 380;
		textBoxSaveDirectory.Width = 300;
		UpdateVoiceEffectLabels();
		progressBarTts.Style = ProgressBarStyle.Blocks;
		progressBarTts.Height = 18;
		progressBarTts.Value = 0;
		labelProgressStatus.Text = "";
		StyleButton(buttonGenerateAudio, Color.FromArgb(30, 92, 180), Color.White, bold: true);
		StyleButton(buttonPlayGenerated, Color.FromArgb(230, 235, 243), Color.FromArgb(45, 55, 72), bold: false);
		StyleButton(buttonStopGenerated, Color.FromArgb(230, 235, 243), Color.FromArgb(45, 55, 72), bold: false);
		Button[] array2 = new Button[8]
		{
			buttonLoadFile, buttonPlaySample, buttonSelectFolder, buttonOpenFolder, buttonSaveSettings,
			buttonOpenModelFolder, buttonOpenLog, buttonOpenBlog
		};
		foreach (Button button in array2)
		{
			StyleButton(button, Color.White, Color.FromArgb(45, 55, 72), bold: false);
		}
		if (comboBoxQuality.Items.Count == 0 || !comboBoxQuality.Items.Contains("균형"))
		{
			comboBoxQuality.Items.Clear();
			comboBoxQuality.Items.Add("빠른 생성");
			comboBoxQuality.Items.Add("균형");
			comboBoxQuality.Items.Add("고품질");
			comboBoxQuality.SelectedIndex = 2;
		}
		TableLayoutPanel tableLayoutPanel = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			Padding = new Padding(16),
			ColumnCount = 1,
			RowCount = 2,
			BackColor = BackColor
		};
		tableLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
		tableLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 76f));
		TableLayoutPanel tableLayoutPanel2 = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			ColumnCount = 2,
			RowCount = 1
		};
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42f));
		Panel panel = CreateCardPanel();
		panel.Margin = new Padding(0, 0, 12, 0);
		TableLayoutPanel tableLayoutPanel3 = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 5,
			Padding = new Padding(16)
		};
		tableLayoutPanel3.RowStyles.Add(new RowStyle(SizeType.Absolute, 28f));
		tableLayoutPanel3.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
		tableLayoutPanel3.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
		tableLayoutPanel3.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
		tableLayoutPanel3.RowStyles.Add(new RowStyle(SizeType.Absolute, 18f));
		labelTitle.Font = new Font(Font, FontStyle.Bold);
		labelTitle.Dock = DockStyle.Fill;
		TableLayoutPanel tableLayoutPanel4 = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			ColumnCount = 2
		};
		tableLayoutPanel4.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		tableLayoutPanel4.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 142f));
		textBoxTitle.Dock = DockStyle.Fill;
		buttonLoadFile.Dock = DockStyle.Fill;
		tableLayoutPanel4.Controls.Add(textBoxTitle, 0, 0);
		tableLayoutPanel4.Controls.Add(buttonLoadFile, 1, 0);
		FlowLayoutPanel contentHeader = new FlowLayoutPanel
		{
			Dock = DockStyle.Fill,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = false,
			Padding = new Padding(0, 6, 0, 0)
		};
		labelContent.Font = new Font(Font, FontStyle.Bold);
		labelContent.Width = 95;
		labelContent.TextAlign = ContentAlignment.MiddleLeft;
		contentHeader.Controls.Add(labelContent);
		tableLayoutPanel3.Controls.Add(labelTitle, 0, 0);
		tableLayoutPanel3.Controls.Add(tableLayoutPanel4, 0, 1);
		tableLayoutPanel3.Controls.Add(contentHeader, 0, 2);
		tableLayoutPanel3.Controls.Add(richTextBoxContent, 0, 3);
		panel.Controls.Add(tableLayoutPanel3);
		Panel panel2 = CreateCardPanel();
		panel2.Margin = new Padding(0);
		TableLayoutPanel tableLayoutPanel5 = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			AutoScroll = true,
			ColumnCount = 1,
			RowCount = 10,
			Padding = new Padding(14)
		};
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		tableLayoutPanel5.Controls.Add(CreateEngineSection(), 0, 0);
		tableLayoutPanel5.Controls.Add(CreateModelSection(), 0, 1);
		tableLayoutPanel5.Controls.Add(CreateVoiceSection(), 0, 2);
		tableLayoutPanel5.Controls.Add(CreateQualitySection(), 0, 3);
		tableLayoutPanel5.Controls.Add(CreateToneSection(), 0, 4);
		tableLayoutPanel5.Controls.Add(CreateGuideSection(), 0, 5);
		tableLayoutPanel5.Controls.Add(CreatePronunciationSection(), 0, 6);
		tableLayoutPanel5.Controls.Add(CreateSaveSection(), 0, 7);
		tableLayoutPanel5.Controls.Add(CreateDeveloperSection(), 0, 8);
		tableLayoutPanel5.Controls.Add(buttonSaveSettings, 0, 9);
		buttonSaveSettings.Dock = DockStyle.Top;
		buttonSaveSettings.Height = 42;
		panel2.Controls.Add(tableLayoutPanel5);
		tableLayoutPanel2.Controls.Add(panel, 0, 0);
		tableLayoutPanel2.Controls.Add(panel2, 1, 0);
		Panel panel3 = CreateCardPanel();
		panel3.Margin = new Padding(0, 12, 0, 0);
		TableLayoutPanel tableLayoutPanel6 = new TableLayoutPanel
		{
			Dock = DockStyle.Fill,
			ColumnCount = 5,
			RowCount = 1,
			Padding = new Padding(12, 10, 12, 10)
		};
		tableLayoutPanel6.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170f));
		tableLayoutPanel6.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92f));
		tableLayoutPanel6.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92f));
		tableLayoutPanel6.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		tableLayoutPanel6.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 260f));
		buttonGenerateAudio.Dock = DockStyle.Fill;
		buttonPlayGenerated.Dock = DockStyle.Fill;
		buttonStopGenerated.Dock = DockStyle.Fill;
		progressBarTts.Dock = DockStyle.Fill;
		labelProgressStatus.Dock = DockStyle.Fill;
		labelProgressStatus.TextAlign = ContentAlignment.MiddleLeft;
		tableLayoutPanel6.Controls.Add(buttonGenerateAudio, 0, 0);
		tableLayoutPanel6.Controls.Add(buttonPlayGenerated, 1, 0);
		tableLayoutPanel6.Controls.Add(buttonStopGenerated, 2, 0);
		tableLayoutPanel6.Controls.Add(progressBarTts, 3, 0);
		tableLayoutPanel6.Controls.Add(labelProgressStatus, 4, 0);
		panel3.Controls.Add(tableLayoutPanel6);
		tableLayoutPanel.Controls.Add(tableLayoutPanel2, 0, 0);
		tableLayoutPanel.Controls.Add(panel3, 0, 1);
		base.Controls.Add(tableLayoutPanel);
		ResumeLayout(performLayout: true);
	}

	private Panel CreateCardPanel()
	{
		return new Panel
		{
			Dock = DockStyle.Fill,
			Padding = new Padding(0),
			Margin = new Padding(0),
			BackColor = Color.White,
			BorderStyle = BorderStyle.FixedSingle
		};
	}

	private Label CreateHeader(string text)
	{
		return new Label
		{
			Text = text,
			AutoSize = false,
			Height = 24,
			Dock = DockStyle.Top,
			Font = new Font(Font, FontStyle.Bold),
			ForeColor = Color.FromArgb(32, 45, 64),
			TextAlign = ContentAlignment.MiddleLeft
		};
	}

	private void StyleButton(Button button, Color backColor, Color foreColor, bool bold)
	{
		button.FlatStyle = FlatStyle.Flat;
		button.FlatAppearance.BorderColor = Color.FromArgb(190, 200, 214);
		button.FlatAppearance.BorderSize = 1;
		button.BackColor = backColor;
		button.ForeColor = foreColor;
		button.Font = new Font(Font, bold ? FontStyle.Bold : FontStyle.Regular);
		button.UseVisualStyleBackColor = false;
		button.Margin = new Padding(4);
	}

	private void ConfigureDeveloperXButton()
	{
		buttonOpenBlog.Text = "개발자 바로가기";
		buttonOpenBlog.Height = 38;
		buttonOpenBlog.BackColor = Color.FromArgb(10, 10, 10);
		buttonOpenBlog.ForeColor = Color.White;
		buttonOpenBlog.FlatStyle = FlatStyle.Flat;
		buttonOpenBlog.FlatAppearance.BorderColor = Color.FromArgb(10, 10, 10);
		buttonOpenBlog.FlatAppearance.BorderSize = 1;
		buttonOpenBlog.Font = new Font(Font, FontStyle.Bold);
		buttonOpenBlog.TextAlign = ContentAlignment.MiddleCenter;
		buttonOpenBlog.ImageAlign = ContentAlignment.MiddleLeft;
		buttonOpenBlog.TextImageRelation = TextImageRelation.ImageBeforeText;
		buttonOpenBlog.Padding = new Padding(12, 0, 12, 0);
		Image image = LoadButtonImage("x_logo.png", 22, 22);
		if (image != null)
		{
			buttonOpenBlog.Image = image;
		}
	}

	private Image LoadButtonImage(string fileName, int width, int height)
	{
		try
		{
			string path = Path.Combine(InternalRoot, fileName);
			if (!File.Exists(path))
			{
				return null;
			}
			using FileStream stream = File.OpenRead(path);
			using Image original = Image.FromStream(stream);
			return new Bitmap(original, new Size(width, height));
		}
		catch
		{
			return null;
		}
	}

	private Control CreateEngineSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("엔진"), 0, 0);
		comboBoxEngine.Dock = DockStyle.Top;
		tableLayoutPanel.Controls.Add(comboBoxEngine, 0, 1);
		return tableLayoutPanel;
	}

	private Control CreateModelSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("모델 상태"), 0, 0);
		labelModelStatus.Height = 36;
		tableLayoutPanel.Controls.Add(labelModelStatus, 0, 1);
		FlowLayoutPanel flowLayoutPanel = new FlowLayoutPanel
		{
			Dock = DockStyle.Top,
			Height = 38,
			WrapContents = false
		};
		flowLayoutPanel.Controls.Add(buttonOpenModelFolder);
		flowLayoutPanel.Controls.Add(buttonOpenLog);
		tableLayoutPanel.Controls.Add(flowLayoutPanel, 0, 2);
		return tableLayoutPanel;
	}

	private Control CreateVoiceSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("음성"), 0, 0);
		TableLayoutPanel tableLayoutPanel2 = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 2,
			Height = 38
		};
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 82f));
		comboBoxVoice.Dock = DockStyle.Fill;
		buttonPlaySample.Dock = DockStyle.Fill;
		tableLayoutPanel2.Controls.Add(comboBoxVoice, 0, 0);
		tableLayoutPanel2.Controls.Add(buttonPlaySample, 1, 0);
		tableLayoutPanel.Controls.Add(tableLayoutPanel2, 0, 1);
		comboBoxVoice.SelectedIndexChanged += delegate
		{
			UpdateVoxReferenceControls();
		};
		panelVoxReference = new Panel
		{
			Dock = DockStyle.Top,
			Height = 112,
			Margin = new Padding(0, 4, 0, 0)
		};
		FlowLayoutPanel buttons = new FlowLayoutPanel
		{
			Dock = DockStyle.Top,
			Height = 38,
			WrapContents = false,
			Padding = new Padding(0)
		};
		buttonSelectReferenceWav = new Button { Text = "WAV 선택", AutoSize = true, Height = 30 };
		buttonPlayReferenceWav = new Button { Text = "참조 재생", AutoSize = true, Height = 30, Enabled = false };
		buttonClearReferenceWav = new Button { Text = "참조 제거", AutoSize = true, Height = 30, Enabled = false };
		buttonSelectReferenceWav.Click += buttonSelectReferenceWav_Click;
		buttonPlayReferenceWav.Click += buttonPlayReferenceWav_Click;
		buttonClearReferenceWav.Click += buttonClearReferenceWav_Click;
		StyleButton(buttonSelectReferenceWav, Color.White, Color.FromArgb(45, 55, 72), bold: false);
		StyleButton(buttonPlayReferenceWav, Color.White, Color.FromArgb(45, 55, 72), bold: false);
		StyleButton(buttonClearReferenceWav, Color.White, Color.FromArgb(45, 55, 72), bold: false);
		buttons.Controls.Add(buttonSelectReferenceWav);
		buttons.Controls.Add(buttonPlayReferenceWav);
		buttons.Controls.Add(buttonClearReferenceWav);
		labelVoxReferenceStatus = new Label
		{
			Dock = DockStyle.Top,
			Height = 28,
			Text = "선택된 참조 WAV 없음",
			AutoEllipsis = true,
			TextAlign = ContentAlignment.MiddleLeft
		};
		labelVoxReferenceNotice = new Label
		{
			Dock = DockStyle.Top,
			Height = 42,
			ForeColor = Color.FromArgb(150, 75, 35),
			Text = "본인이 소유하거나 사용 권한을 가진 5~30초 WAV만 사용하세요.",
			TextAlign = ContentAlignment.MiddleLeft
		};
		panelVoxReference.Controls.Add(labelVoxReferenceNotice);
		panelVoxReference.Controls.Add(labelVoxReferenceStatus);
		panelVoxReference.Controls.Add(buttons);
		tableLayoutPanel.Controls.Add(panelVoxReference, 0, 2);
		return tableLayoutPanel;
	}

	private Control CreateQualitySection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("속도와 품질"), 0, 0);
		TableLayoutPanel tableLayoutPanel2 = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 3,
			Height = 52
		};
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 48f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 72f));
		labelSpeed.Dock = DockStyle.Fill;
		labelSpeed.TextAlign = ContentAlignment.MiddleLeft;
		trackBarSpeed.Dock = DockStyle.Fill;
		labelSpeedValue.Dock = DockStyle.Fill;
		labelSpeedValue.TextAlign = ContentAlignment.MiddleRight;
		tableLayoutPanel2.Controls.Add(labelSpeed, 0, 0);
		tableLayoutPanel2.Controls.Add(trackBarSpeed, 1, 0);
		tableLayoutPanel2.Controls.Add(labelSpeedValue, 2, 0);
		tableLayoutPanel.Controls.Add(tableLayoutPanel2, 0, 1);
		labelQuality.Dock = DockStyle.Top;
		labelQuality.Height = 24;
		comboBoxQuality.Dock = DockStyle.Top;
		comboBoxQuality.Height = 32;
		tableLayoutPanel.Controls.Add(labelQuality, 0, 2);
		tableLayoutPanel.Controls.Add(comboBoxQuality, 0, 3);
		return tableLayoutPanel;
	}

	private Control CreateToneSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("감정과 톤"), 0, 0);
		comboBoxTonePreset.Dock = DockStyle.Top;
		tableLayoutPanel.Controls.Add(comboBoxTonePreset, 0, 1);
		tableLayoutPanel.Controls.Add(CreateEffectSliderRow(labelPitch, trackBarPitch, labelPitchValue), 0, 2);
		tableLayoutPanel.Controls.Add(CreateEffectSliderRow(labelVolume, trackBarVolume, labelVolumeValue), 0, 3);
		tableLayoutPanel.Controls.Add(CreateEffectSliderRow(labelPause, trackBarPause, labelPauseValue), 0, 4);
		return tableLayoutPanel;
	}

	private Control CreateEffectSliderRow(Label titleLabel, TrackBar trackBar, Label valueLabel)
	{
		TableLayoutPanel obj = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 3,
			Height = 44,
			Margin = new Padding(0, 3, 0, 0),
			ColumnStyles = 
			{
				new ColumnStyle(SizeType.Absolute, 48f),
				new ColumnStyle(SizeType.Percent, 100f),
				new ColumnStyle(SizeType.Absolute, 96f)
			}
		};
		titleLabel.Dock = DockStyle.Fill;
		titleLabel.TextAlign = ContentAlignment.MiddleLeft;
		trackBar.Dock = DockStyle.Fill;
		trackBar.Margin = new Padding(0);
		valueLabel.Dock = DockStyle.Fill;
		valueLabel.TextAlign = ContentAlignment.MiddleRight;
		obj.Controls.Add(titleLabel, 0, 0);
		obj.Controls.Add(trackBar, 1, 0);
		obj.Controls.Add(valueLabel, 2, 0);
		return obj;
	}

	private Control CreateGuideSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(labelGuide, 0, 0);
		labelGuide.Text = "안내";
		labelGuide.Font = new Font(Font, FontStyle.Bold);
		labelGuide.Height = 24;
		labelGuide.Dock = DockStyle.Top;
		richTextBoxGuide.Dock = DockStyle.Top;
		tableLayoutPanel.Controls.Add(richTextBoxGuide, 0, 1);
		return tableLayoutPanel;
	}

	private Control CreatePronunciationSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("발음 보정"), 0, 0);
		TableLayoutPanel sibilantRow = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 3,
			Height = 36
		};
		sibilantRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125f));
		sibilantRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		sibilantRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 88f));
		checkBoxSibilantRescue = new CheckBox
		{
			Text = "ㅅ 발음 안정화",
			Checked = true,
			Dock = DockStyle.Fill,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft
		};
		checkBoxSibilantRescue.CheckedChanged += delegate
		{
			comboBoxSibilantMode.Enabled = checkBoxSibilantRescue.Checked;
			UpdateSibilantDebugButton();
		};
		comboBoxSibilantMode = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Dock = DockStyle.Fill
		};
		comboBoxSibilantMode.Items.AddRange(new object[] { "가볍게", "기본", "강하게", "디버그" });
		comboBoxSibilantMode.SelectedItem = "기본";
		comboBoxSibilantMode.SelectedIndexChanged += delegate
		{
			UpdateSibilantDebugButton();
		};
		buttonSibilantDebug = new Button
		{
			Text = "후보 생성",
			Dock = DockStyle.Fill,
			Enabled = false,
			UseVisualStyleBackColor = true
		};
		StyleButton(buttonSibilantDebug, Color.White, Color.FromArgb(45, 55, 72), bold: false);
		buttonSibilantDebug.Click += async delegate
		{
			await CreateSibilantDebugSamplesAsync();
		};
		sibilantRow.Controls.Add(checkBoxSibilantRescue, 0, 0);
		sibilantRow.Controls.Add(comboBoxSibilantMode, 1, 0);
		sibilantRow.Controls.Add(buttonSibilantDebug, 2, 0);
		tableLayoutPanel.Controls.Add(sibilantRow, 0, 1);
		TableLayoutPanel tableLayoutPanel2 = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 1,
			Height = 38
		};
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		buttonPreviewPronunciation = new Button
		{
			Text = "발음 미리보기",
			Dock = DockStyle.Fill,
			Height = 30,
			UseVisualStyleBackColor = true
		};
		buttonPreviewPronunciation.Click += buttonPreviewPronunciation_Click;
		tableLayoutPanel2.Controls.Add(buttonPreviewPronunciation, 0, 0);
		tableLayoutPanel.Controls.Add(tableLayoutPanel2, 0, 2);
		UpdateSibilantDebugButton();
		return tableLayoutPanel;
	}

	private Control CreateSaveSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("저장"), 0, 0);
		TableLayoutPanel tableLayoutPanel2 = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			ColumnCount = 3,
			Height = 38
		};
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 42f));
		tableLayoutPanel2.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 58f));
		textBoxSaveDirectory.Dock = DockStyle.Fill;
		buttonSelectFolder.Dock = DockStyle.Fill;
		buttonOpenFolder.Dock = DockStyle.Fill;
		tableLayoutPanel2.Controls.Add(textBoxSaveDirectory, 0, 0);
		tableLayoutPanel2.Controls.Add(buttonSelectFolder, 1, 0);
		tableLayoutPanel2.Controls.Add(buttonOpenFolder, 2, 0);
		tableLayoutPanel.Controls.Add(tableLayoutPanel2, 0, 1);
		return tableLayoutPanel;
	}

	private Control CreateDeveloperSection()
	{
		TableLayoutPanel tableLayoutPanel = CreateSectionPanel();
		tableLayoutPanel.Controls.Add(CreateHeader("바로가기"), 0, 0);
		FlowLayoutPanel flowLayoutPanel = new FlowLayoutPanel
		{
			AutoSize = true,
			BackColor = Color.Transparent,
			Dock = DockStyle.Top,
			FlowDirection = FlowDirection.LeftToRight,
			Margin = new Padding(0, 4, 0, 0),
			Padding = new Padding(0),
			WrapContents = false
		};
		FlowLayoutPanel flowLayoutPanel2 = new FlowLayoutPanel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			BackColor = Color.FromArgb(10, 10, 10),
			Cursor = Cursors.Hand,
			FlowDirection = FlowDirection.LeftToRight,
			Height = 38,
			Margin = new Padding(0),
			Padding = new Padding(14, 7, 14, 7),
			WrapContents = false
		};
		Label label = CreateDeveloperLinkLabel("개발자");
		PictureBox pictureBox = new PictureBox
		{
			Image = LoadButtonImage("x_logo.png", 22, 22),
			Margin = new Padding(6, 1, 6, 0),
			Size = new Size(22, 22),
			SizeMode = PictureBoxSizeMode.StretchImage
		};
		Label label2 = CreateDeveloperLinkLabel("바로가기");
		EventHandler value = buttonOpenBlog_Click;
		flowLayoutPanel2.Click += value;
		label.Click += value;
		pictureBox.Click += value;
		label2.Click += value;
		flowLayoutPanel2.Controls.Add(label);
		flowLayoutPanel2.Controls.Add(pictureBox);
		flowLayoutPanel2.Controls.Add(label2);
		flowLayoutPanel.Controls.Add(flowLayoutPanel2);
		tableLayoutPanel.Controls.Add(flowLayoutPanel, 0, 1);
		return tableLayoutPanel;
	}

	private Label CreateDeveloperLinkLabel(string text)
	{
		return new Label
		{
			AutoSize = true,
			BackColor = Color.FromArgb(10, 10, 10),
			Font = new Font(Font, FontStyle.Bold),
			ForeColor = Color.White,
			Margin = new Padding(0, 2, 0, 0),
			Text = text,
			TextAlign = ContentAlignment.MiddleCenter
		};
	}

	private TableLayoutPanel CreateSectionPanel()
	{
		return new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			ColumnCount = 1,
			Padding = new Padding(0, 0, 0, 6),
			Margin = new Padding(0, 0, 0, 4)
		};
	}

	private bool IsSupertonicSelected()
	{
		return SelectedEngine == TtsEngineKind.Supertonic;
	}

	private TtsEngineKind SelectedEngine =>
		string.Equals(comboBoxEngine?.SelectedItem?.ToString(), EngineHiggs, StringComparison.Ordinal)
			? TtsEngineKind.HiggsAudioV3
			: string.Equals(comboBoxEngine?.SelectedItem?.ToString(), EngineVoxCpm2, StringComparison.Ordinal)
				? TtsEngineKind.VoxCpm2
				: TtsEngineKind.Supertonic;

	private void LoadVoiceOptionsForEngine()
	{
		string voiceId = (comboBoxVoice.SelectedItem as VoiceItem)?.VoiceId ?? "";
		comboBoxVoice.Items.Clear();
		if (IsSupertonicSelected())
		{
			comboBoxVoice.Items.Add(new VoiceItem("M1", "M1 - 밝고 자신감 있는 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("M2", "M2 - 낮고 차분한 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("M3", "M3 - 신뢰감 있는 발표형 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("M4", "M4 - 부드럽고 친근한 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("M5", "M5 - 따뜻한 스토리텔링 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("F1", "F1 - 차분하고 안정적인 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("F2", "F2 - 밝고 경쾌한 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("F3", "F3 - 선명한 아나운서형 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("F4", "F4 - 자신감 있는 설명형 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("F5", "F5 - 부드럽고 다정한 여성"));
		}
		else if (IsHiggsSelected())
		{
			LoadHiggsVoiceOptions();
		}
		else
		{
			comboBoxVoice.Items.Add(new VoiceItem("vox_news_f", "뉴스 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("vox_calm_f", "차분한 여성 내레이션"));
			comboBoxVoice.Items.Add(new VoiceItem("vox_emotive_f", "감정 연기 여성"));
			comboBoxVoice.Items.Add(new VoiceItem("vox_trust_m", "신뢰감 있는 남성"));
			comboBoxVoice.Items.Add(new VoiceItem("vox_clone", "내 WAV 음성 복제"));
		}
		if (!IsSupertonicSelected() && string.IsNullOrWhiteSpace(voiceId))
		{
			voiceId = IsHiggsSelected() ? "higgs_default" : "vox_news_f";
		}
		SelectVoiceById(voiceId);
	}

	private void LoadHiggsVoiceOptions()
	{
		comboBoxVoice.Items.Add(new VoiceItem("higgs_default", "Model default voice"));
		string voicesDir = Path.Combine(GetHiggsRuntimeRoot(), "voices");
		if (Directory.Exists(voicesDir))
		{
			try
			{
				string[] wavFiles = Directory.GetFiles(voicesDir, "*.wav", SearchOption.TopDirectoryOnly);
				foreach (string wavFile in wavFiles.OrderBy(f => Path.GetFileNameWithoutExtension(f)))
				{
					string voiceId = Path.GetFileNameWithoutExtension(wavFile);
					if (!voiceId.EndsWith(".lowmem", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							WavData wavData = ReadWavData(File.ReadAllBytes(wavFile));
							if (wavData.AudioFormat != 1 || wavData.BitsPerSample != 16 || wavData.Channels != 1 || wavData.SampleRate != 24000)
							{
								AppendHiggsLog($"Warning: voice file {voiceId} has unsupported format ({wavData.SampleRate}Hz, {wavData.Channels}ch, {wavData.BitsPerSample}bit). 24kHz mono 16-bit required.");
								continue;
							}
							comboBoxVoice.Items.Add(new VoiceItem(voiceId, voiceId));
						}
						catch (Exception ex)
						{
							AppendHiggsLog($"Warning: failed to load voice file {voiceId}: {ex.Message}");
						}
					}
				}
			}
			catch
			{
			}
		}
	}

	private void SelectVoiceById(string voiceId)
	{
		if (!string.IsNullOrWhiteSpace(voiceId))
		{
			for (int i = 0; i < comboBoxVoice.Items.Count; i++)
			{
				if (((VoiceItem)comboBoxVoice.Items[i]).VoiceId == voiceId)
				{
					comboBoxVoice.SelectedIndex = i;
					return;
				}
			}
		}
		if (comboBoxVoice.Items.Count > 0)
		{
			comboBoxVoice.SelectedIndex = 0;
		}
	}

	private void UpdateEngineUiVisibility()
	{
		bool isSupertonic = IsSupertonicSelected();
		labelSpeed.Visible = true;
		trackBarSpeed.Visible = true;
		labelSpeedValue.Visible = true;
		labelQuality.Visible = true;
		comboBoxQuality.Visible = true;
		labelTonePreset.Visible = isSupertonic;
		comboBoxTonePreset.Visible = isSupertonic;
		labelPitch.Visible = isSupertonic;
		trackBarPitch.Visible = isSupertonic;
		labelPitchValue.Visible = isSupertonic;
		labelVolume.Visible = true;
		trackBarVolume.Visible = true;
		labelVolumeValue.Visible = true;
		labelPause.Visible = true;
		trackBarPause.Visible = true;
		labelPauseValue.Visible = true;
		if (panelVoxReference != null)
		{
			panelVoxReference.Visible = !isSupertonic;
		}
		if (buttonPreviewPronunciation != null)
		{
			buttonPreviewPronunciation.Visible = isSupertonic;
		}
		if (checkBoxSibilantRescue != null)
		{
			checkBoxSibilantRescue.Visible = isSupertonic;
		}
		if (comboBoxSibilantMode != null)
		{
			comboBoxSibilantMode.Visible = isSupertonic;
			comboBoxSibilantMode.Enabled = isSupertonic && IsSibilantRescueEnabled;
		}
		UpdateSibilantDebugButton();
		buttonPlaySample.Text = "샘플";
		UpdateVoxReferenceControls();
		UpdateModelStatusLabel();
		LoadEngineGuide();
		NormalizeGuideText();
	}

	private void NormalizeGuideText()
	{
		if (IsSupertonicSelected())
		{
			labelGuide.Text = "Supertonic 안내";
			richTextBoxGuide.Text = "로컬 ONNX 모델로 생성합니다.\n\n- API 키 없이 사용\n- Supertonic 직접 옵션: 음성, 속도, 품질, 쉼\n- 피치 강제 변조는 음질 보호를 위해 비활성화\n- 법정 변론 프리셋은 M1/고품질/안정 호흡으로 고정합니다.";
		}
		else
		{
			labelGuide.Text = "VoxCPM2 안내";
			richTextBoxGuide.Text = "고품질 CPU 모델로 생성합니다.\n\n- 뉴스 여성 기본 프리셋\n- 프리셋 4종과 5~30초 WAV 음성 복제\n- 220자 단위 자동 분할 및 병합\n- 모델 로딩과 생성에는 수 분이 걸릴 수 있습니다.";
		}
	}

	private void comboBoxEngine_SelectedIndexChanged(object sender, EventArgs e)
	{
		if (suppressEngineSelectionChanged)
		{
			return;
		}
		if (!loadingSettings)
		{
			CaptureEngineControlState(lastSelectedEngine);
		}
		if (IsSupertonicSelected())
		{
			if (!StopVoxServer())
			{
				suppressEngineSelectionChanged = true;
				try { comboBoxEngine.SelectedItem = EngineVoxCpm2; }
				finally { suppressEngineSelectionChanged = false; }
				LoadVoiceOptionsForEngine();
				ApplyEngineControlState(TtsEngineKind.VoxCpm2);
				lastSelectedEngine = TtsEngineKind.VoxCpm2;
				UpdateEngineUiVisibility();
				MessageBox.Show("VoxCPM2 서버 프로세스 트리의 종료를 확인하지 못해 엔진 전환을 중단했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.", "VoxCPM2 종료 확인 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}
		}
		else
		{
			StopSupertonicServer();
		}
		LoadVoiceOptionsForEngine();
		if (!loadingSettings)
		{
			ApplyEngineControlState(SelectedEngine);
		}
		lastSelectedEngine = SelectedEngine;
		UpdateEngineUiVisibility();
		QueueSupertonicSampleWarmup();
	}

	private void CaptureEngineControlState(TtsEngineKind engine)
	{
		VoiceItem voice = comboBoxVoice?.SelectedItem as VoiceItem;
		if (engine == TtsEngineKind.Supertonic)
		{
			cachedSupertonicVoice = voice?.VoiceId ?? cachedSupertonicVoice;
			cachedSupertonicSpeed = trackBarSpeed?.Value ?? cachedSupertonicSpeed;
			cachedSupertonicQuality = comboBoxQuality?.SelectedItem?.ToString() ?? cachedSupertonicQuality;
			cachedSupertonicVolume = trackBarVolume?.Value ?? cachedSupertonicVolume;
			cachedSupertonicPause = trackBarPause?.Value ?? cachedSupertonicPause;
			cachedSupertonicTone = comboBoxTonePreset?.SelectedItem?.ToString() ?? cachedSupertonicTone;
		}
		else if (engine == TtsEngineKind.HiggsAudioV3)
		{
			cachedHiggsVoice = voice?.VoiceId ?? cachedHiggsVoice;
			cachedHiggsSpeed = trackBarSpeed?.Value ?? cachedHiggsSpeed;
			cachedHiggsQuality = comboBoxQuality?.SelectedItem?.ToString() ?? cachedHiggsQuality;
			cachedHiggsVolume = trackBarVolume?.Value ?? cachedHiggsVolume;
			cachedHiggsPause = trackBarPause?.Value ?? cachedHiggsPause;
			cachedHiggsTone = comboBoxTonePreset?.SelectedItem?.ToString() ?? cachedHiggsTone;
		}
		else
		{
			cachedVoxVoice = voice?.VoiceId ?? cachedVoxVoice;
			cachedVoxSpeed = trackBarSpeed?.Value ?? cachedVoxSpeed;
			cachedVoxQuality = comboBoxQuality?.SelectedItem?.ToString() ?? cachedVoxQuality;
			cachedVoxVolume = trackBarVolume?.Value ?? cachedVoxVolume;
			cachedVoxPause = trackBarPause?.Value ?? cachedVoxPause;
		}
	}

	private void ApplyEngineControlState(TtsEngineKind engine)
	{
		bool supertonic = engine == TtsEngineKind.Supertonic;
		bool higgs = engine == TtsEngineKind.HiggsAudioV3;
		string voiceId = supertonic ? cachedSupertonicVoice : (higgs ? cachedHiggsVoice : cachedVoxVoice);
		SelectVoiceById(voiceId);
		int speed = supertonic ? cachedSupertonicSpeed : (higgs ? cachedHiggsSpeed : cachedVoxSpeed);
		trackBarSpeed.Value = Math.Max(trackBarSpeed.Minimum, Math.Min(trackBarSpeed.Maximum, speed));
		string quality = supertonic ? cachedSupertonicQuality : (higgs ? cachedHiggsQuality : cachedVoxQuality);
		comboBoxQuality.SelectedItem = comboBoxQuality.Items.Contains(quality) ? quality : "고품질";
		if (supertonic)
		{
			comboBoxTonePreset.SelectedItem = comboBoxTonePreset.Items.Contains(cachedSupertonicTone) ? cachedSupertonicTone : "기본";
		}
		else if (higgs && comboBoxTonePreset != null)
		{
			comboBoxTonePreset.SelectedItem = comboBoxTonePreset.Items.Contains(cachedHiggsTone) ? cachedHiggsTone : "기본";
		}
		int volume = supertonic ? cachedSupertonicVolume : (higgs ? cachedHiggsVolume : cachedVoxVolume);
		int pause = supertonic ? cachedSupertonicPause : (higgs ? cachedHiggsPause : cachedVoxPause);
		trackBarVolume.Value = Math.Max(trackBarVolume.Minimum, Math.Min(trackBarVolume.Maximum, volume));
		trackBarPause.Value = Math.Max(trackBarPause.Minimum, Math.Min(trackBarPause.Maximum, pause));
		UpdateVoiceEffectLabels();
		UpdateVoxReferenceControls();
	}

	private void trackBarSpeed_ValueChanged(object sender, EventArgs e)
	{
		labelSpeedValue.Text = GetSelectedSpeed().ToString("0.00") + "x";
	}

	private void comboBoxQuality_SelectedIndexChanged(object sender, EventArgs e)
	{
	}

	private void comboBoxTonePreset_SelectedIndexChanged(object sender, EventArgs e)
	{
		if (!applyingTonePreset)
		{
			ApplyTonePresetDefaults();
		}
	}

	private void voiceEffect_ValueChanged(object sender, EventArgs e)
	{
		UpdateVoiceEffectLabels();
	}

	private void ApplyTonePresetDefaults()
	{
		if (comboBoxTonePreset == null || trackBarPitch == null || trackBarVolume == null || trackBarPause == null)
		{
			return;
		}
		string text = comboBoxTonePreset.SelectedItem?.ToString() ?? "기본";
		if (text == "사용자 설정")
		{
			UpdateVoiceEffectLabels();
			return;
		}
		int val = 0;
		int val2 = 100;
		int val3 = 25;
		switch (text)
		{
		case "밝고 활기차게":
			val = 0;
			val2 = 108;
			val3 = 18;
			break;
		case "차분하고 부드럽게":
			val = 0;
			val2 = 96;
			val3 = 35;
			break;
		case "힘있고 또렷하게":
			val = 0;
			val2 = 115;
			val3 = 22;
			break;
		case TonePresetCourtPleading:
			val = 0;
			val2 = 112;
			val3 = 34;
			break;
		case "낮고 진지하게":
			val = 0;
			val2 = 105;
			val3 = 32;
			break;
		case "부드러운 속삭임":
			val = 0;
			val2 = 82;
			val3 = 38;
			break;
		case "긴장감 있게":
			val = 0;
			val2 = 110;
			val3 = 15;
			break;
		case "캐릭터 높게":
		case "캐릭터 밝게":
			val = 0;
			val2 = 105;
			val3 = 20;
			break;
		}
		applyingTonePreset = true;
		if (text == TonePresetCourtPleading && IsSupertonicSelected())
		{
			SelectVoiceById("M1");
			if (comboBoxQuality.Items.Contains("고품질"))
			{
				comboBoxQuality.SelectedItem = "고품질";
			}
			trackBarSpeed.Value = Math.Max(trackBarSpeed.Minimum, Math.Min(trackBarSpeed.Maximum, 105));
		}
		trackBarPitch.Value = Math.Max(trackBarPitch.Minimum, Math.Min(trackBarPitch.Maximum, val));
		trackBarVolume.Value = Math.Max(trackBarVolume.Minimum, Math.Min(trackBarVolume.Maximum, val2));
		trackBarPause.Value = Math.Max(trackBarPause.Minimum, Math.Min(trackBarPause.Maximum, val3));
		applyingTonePreset = false;
		UpdateVoiceEffectLabels();
	}

	private void UpdateVoiceEffectLabels()
	{
		if (labelPitchValue != null && trackBarPitch != null)
		{
			labelPitchValue.Text = "자연 고정";
			labelPitchValue.AutoEllipsis = true;
		}
		if (labelVolumeValue != null && trackBarVolume != null)
		{
			labelVolumeValue.Text = trackBarVolume.Value + "%";
		}
		if (labelPauseValue != null && trackBarPause != null)
		{
			labelPauseValue.Text = GetSelectedSilenceDuration().ToString("0.00") + "s";
		}
	}

	private string GetSupertonicModelDirectory()
	{
		return Path.Combine(InternalRoot, "SupertonicLocal", "models");
	}

	private List<string> GetMissingSupertonicModelFiles()
	{
		string modelDirectory = GetSupertonicModelDirectory();
		return new string[16]
		{
			Path.Combine("onnx", "duration_predictor.onnx"),
			Path.Combine("onnx", "text_encoder.onnx"),
			Path.Combine("onnx", "vector_estimator.onnx"),
			Path.Combine("onnx", "vocoder.onnx"),
			Path.Combine("onnx", "tts.json"),
			Path.Combine("onnx", "unicode_indexer.json"),
			Path.Combine("voice_styles", "M1.json"),
			Path.Combine("voice_styles", "M2.json"),
			Path.Combine("voice_styles", "M3.json"),
			Path.Combine("voice_styles", "M4.json"),
			Path.Combine("voice_styles", "M5.json"),
			Path.Combine("voice_styles", "F1.json"),
			Path.Combine("voice_styles", "F2.json"),
			Path.Combine("voice_styles", "F3.json"),
			Path.Combine("voice_styles", "F4.json"),
			Path.Combine("voice_styles", "F5.json")
		}.Where((string relativePath) => !File.Exists(Path.Combine(modelDirectory, relativePath))).ToList();
	}

	private bool HasSupertonicModelFiles()
	{
		return GetMissingSupertonicModelFiles().Count == 0;
	}

	private void ValidateSupertonicModelOrThrow()
	{
		List<string> missingSupertonicModelFiles = GetMissingSupertonicModelFiles();
		if (missingSupertonicModelFiles.Count > 0)
		{
			throw new FileNotFoundException("Supertonic 3 모델 파일이 없습니다. _internal\\SupertonicLocal\\models 아래에 onnx와 voice_styles 폴더를 넣어주세요.\n누락: " + string.Join(", ", missingSupertonicModelFiles.Take(6)) + ((missingSupertonicModelFiles.Count > 6) ? " ..." : ""));
		}
		string modelDirectory = GetSupertonicModelDirectory();
		foreach ((string relativePath, (long expectedSize, string expectedHash)) in SupertonicModelIntegrity)
		{
			string path = Path.Combine(modelDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar));
			FileInfo info = new FileInfo(path);
			if (info.Length != expectedSize)
			{
				throw new InvalidDataException($"Supertonic 모델 크기 검증에 실패했습니다: {relativePath}");
			}
			using FileStream source = File.OpenRead(path);
			string actualHash = Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
			if (!CryptographicOperations.FixedTimeEquals(
				Encoding.ASCII.GetBytes(actualHash),
				Encoding.ASCII.GetBytes(expectedHash)))
			{
				throw new InvalidDataException($"Supertonic 모델 SHA-256 검증에 실패했습니다: {relativePath}");
			}
		}
	}

	private void UpdateModelStatusLabel()
	{
		if (labelModelStatus == null)
		{
			return;
		}
		if (!IsSupertonicSelected())
		{
			List<string> missingVoxFiles = GetMissingVoxFiles();
			if (missingVoxFiles.Count == 0)
			{
				labelModelStatus.Text = "VoxCPM2 모델 준비 완료 (CPU)";
				labelModelStatus.ForeColor = Color.FromArgb(20, 115, 65);
				buttonGenerateAudio.Enabled = !generationInProgress;
			}
			else
			{
				labelModelStatus.Text = "VoxCPM2 파일 누락: " + missingVoxFiles[0];
				labelModelStatus.ForeColor = Color.FromArgb(180, 75, 35);
				buttonGenerateAudio.Enabled = false;
			}
			return;
		}
		List<string> missingSupertonicModelFiles = GetMissingSupertonicModelFiles();
		if (missingSupertonicModelFiles.Count == 0)
		{
			labelModelStatus.Text = "로컬 모델 준비 완료";
			labelModelStatus.ForeColor = Color.FromArgb(20, 115, 65);
			buttonGenerateAudio.Enabled = true;
		}
		else
		{
			labelModelStatus.Text = "모델 파일 누락: " + missingSupertonicModelFiles[0];
			labelModelStatus.ForeColor = Color.FromArgb(180, 75, 35);
			buttonGenerateAudio.Enabled = false;
		}
	}

	private void LoadSettings()
	{
		try
		{
			if (File.Exists(settingsFilePath))
			{
				JObject jObject = JObject.Parse(File.ReadAllText(settingsFilePath));
				loadingSettings = true;
				cachedSupertonicVoice = jObject["SupertonicVoice"]?.ToString() ?? "F2";
				cachedVoxVoice = jObject["VoxCpm2Voice"]?.ToString() ?? "vox_news_f";
				cachedSupertonicSpeed = jObject["Speed"]?.Value<int>() ?? 105;
				cachedVoxSpeed = jObject["VoxCpm2Speed"]?.Value<int>() ?? 100;
				cachedSupertonicQuality = jObject["Quality"]?.ToString() ?? "균형";
				cachedVoxQuality = jObject["VoxCpm2Quality"]?.ToString() ?? "고품질";
				cachedSupertonicVolume = jObject["Volume"]?.Value<int>() ?? 100;
				cachedVoxVolume = jObject["VoxCpm2Volume"]?.Value<int>() ?? 100;
				cachedSupertonicPause = jObject["Pause"]?.Value<int>() ?? 25;
				cachedVoxPause = jObject["VoxCpm2Pause"]?.Value<int>() ?? 25;
				cachedSupertonicTone = jObject["TonePreset"]?.ToString() ?? "기본";
				string text = jObject["Engine"]?.ToString() ?? EngineSupertonic;
				comboBoxEngine.SelectedItem = string.Equals(text, EngineSupertonic, StringComparison.Ordinal) ? EngineSupertonic : EngineVoxCpm2;
				LoadVoiceOptionsForEngine();
				string text2 = IsSupertonicSelected() ? (jObject["SupertonicVoice"]?.ToString() ?? "F2") : (jObject["VoxCpm2Voice"]?.ToString() ?? "vox_news_f");
				SelectVoiceById(text2);
				int num = jObject["VoiceIndex"]?.Value<int>() ?? (-1);
				if (num >= 0 && num < comboBoxVoice.Items.Count && string.IsNullOrWhiteSpace(text2))
				{
					comboBoxVoice.SelectedIndex = num;
				}
				int val = IsSupertonicSelected() ? (jObject["Speed"]?.Value<int>() ?? 105) : (jObject["VoxCpm2Speed"]?.Value<int>() ?? 100);
				trackBarSpeed.Value = Math.Max(trackBarSpeed.Minimum, Math.Min(trackBarSpeed.Maximum, val));
				string text3 = IsSupertonicSelected() ? (jObject["Quality"]?.ToString() ?? "균형") : (jObject["VoxCpm2Quality"]?.ToString() ?? "고품질");
				comboBoxQuality.SelectedItem = comboBoxQuality.Items.Contains(text3) ? text3 : (IsSupertonicSelected() ? "균형" : "고품질");
				string text4 = jObject["TonePreset"]?.ToString() ?? "기본";
				comboBoxTonePreset.SelectedItem = (comboBoxTonePreset.Items.Contains(text4) ? text4 : "기본");
				if (jObject["Pitch"] != null)
				{
					trackBarPitch.Value = 0;
				}
				int val2 = IsSupertonicSelected() ? (jObject["Volume"]?.Value<int>() ?? 100) : (jObject["VoxCpm2Volume"]?.Value<int>() ?? 100);
				trackBarVolume.Value = Math.Max(trackBarVolume.Minimum, Math.Min(trackBarVolume.Maximum, val2));
				int val3 = IsSupertonicSelected() ? (jObject["Pause"]?.Value<int>() ?? 25) : (jObject["VoxCpm2Pause"]?.Value<int>() ?? 25);
				trackBarPause.Value = Math.Max(trackBarPause.Minimum, Math.Min(trackBarPause.Maximum, val3));
				voxReferenceId = jObject["VoxCpm2ReferenceId"]?.ToString() ?? "";
				voxReferenceDisplayName = Path.GetFileName(jObject["VoxCpm2ReferenceName"]?.ToString() ?? "");
				ResolveStoredVoxReference();
				UpdateVoiceEffectLabels();
				savedAudioPath = ResolveAudioPathSetting(jObject["AudioPath"]?.ToString());
				textBoxSaveDirectory.Text = savedAudioPath;
				if (checkBoxSibilantRescue != null)
				{
					checkBoxSibilantRescue.Checked = jObject["SibilantStabilizationEnabled"]?.Value<bool>() ?? true;
				}
				if (comboBoxSibilantMode != null)
				{
					string mode = PronunciationEngine.SupertonicSibilantRescueNormalizer.ToDisplayMode(
						PronunciationEngine.SupertonicSibilantRescueNormalizer.ParseMode(jObject["SibilantStabilizationMode"]?.ToString() ?? "Medium"));
					comboBoxSibilantMode.SelectedItem = comboBoxSibilantMode.Items.Contains(mode) ? mode : "기본";
					comboBoxSibilantMode.Enabled = IsSibilantRescueEnabled;
				}
				UpdateSibilantDebugButton();
				lastSelectedEngine = SelectedEngine;
				CaptureEngineControlState(lastSelectedEngine);
				loadingSettings = false;
				UpdateEngineUiVisibility();
			}
		}
		catch (Exception ex)
		{
			loadingSettings = false;
			MessageBox.Show("설정을 불러오는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void SaveSettings()
	{
		try
		{
			CaptureEngineControlState(SelectedEngine);
			JObject jObject = new JObject();
			jObject["Engine"] = comboBoxEngine.SelectedItem?.ToString() ?? EngineSupertonic;
			jObject["SupertonicVoice"] = cachedSupertonicVoice;
			jObject["VoiceIndex"] = comboBoxVoice.SelectedIndex;
			jObject["Speed"] = cachedSupertonicSpeed;
			jObject["Quality"] = cachedSupertonicQuality;
			jObject["TonePreset"] = cachedSupertonicTone;
			jObject["Pitch"] = 0;
			jObject["Volume"] = cachedSupertonicVolume;
			jObject["Pause"] = cachedSupertonicPause;
			jObject["AudioPath"] = ToPortablePath(savedAudioPath);
			jObject["SibilantStabilizationEnabled"] = IsSibilantRescueEnabled;
			jObject["SibilantStabilizationMode"] = SelectedSibilantMode.ToString();
			jObject["SibilantPreviewEnabled"] = true;
			jObject["SibilantVoiceProfile"] = "auto";
			jObject["SibilantDebugSaveCandidates"] = true;
			string selectedVoxVoice = cachedVoxVoice;
			jObject["VoxCpm2Voice"] = selectedVoxVoice;
			jObject["VoxCpm2Mode"] = selectedVoxVoice == "vox_clone" ? "clone" : "preset";
			jObject["VoxCpm2ReferenceId"] = voxReferenceId ?? "";
			jObject["VoxCpm2ReferenceName"] = voxReferenceDisplayName ?? "";
			jObject["VoxCpm2Speed"] = cachedVoxSpeed;
			jObject["VoxCpm2Quality"] = cachedVoxQuality;
			jObject["VoxCpm2Volume"] = cachedVoxVolume;
			jObject["VoxCpm2Pause"] = cachedVoxPause;
			jObject["VoxCpm2Seed"] = 42;
			LocalSidecarSecurity.WriteAllTextAtomic(settingsFilePath, jObject.ToString(), Encoding.UTF8);
			MessageBox.Show("설정이 저장되었습니다.", "알림", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
		}
		catch (Exception ex)
		{
			MessageBox.Show("설정을 저장하는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private string GetVoxRoot()
	{
		return Path.Combine(InternalRoot, "VoxCPM2Local");
	}

	private string GetVoxModelDirectory()
	{
		return Path.Combine(GetVoxRoot(), "models", "VoxCPM2");
	}

	private List<string> GetMissingVoxFiles()
	{
		string root = GetVoxRoot();
		List<string> missing = new List<string>();
		string python = Path.Combine(root, "python", "python.exe");
		string server = Path.Combine(root, "app", "server.py");
		string model = Path.Combine(GetVoxModelDirectory(), "model.safetensors");
		string vae = Path.Combine(GetVoxModelDirectory(), "audiovae.pth");
		if (!File.Exists(python)) missing.Add("python\\python.exe");
		if (!File.Exists(server)) missing.Add("app\\server.py");
		if (!File.Exists(model) || new FileInfo(model).Length != VoxModelSize) missing.Add("models\\VoxCPM2\\model.safetensors");
		if (!File.Exists(vae) || new FileInfo(vae).Length != VoxAudioVaeSize) missing.Add("models\\VoxCPM2\\audiovae.pth");
		return missing;
	}

	private void ValidateVoxInstallationOrThrow()
	{
		List<string> missing = GetMissingVoxFiles();
		if (missing.Count > 0)
		{
			throw new FileNotFoundException("VoxCPM2 독립 설치가 완전하지 않습니다. 누락 또는 크기 불일치: " + string.Join(", ", missing));
		}
	}

	private string ResolvePortablePath(string savedPath, string fallbackPath)
	{
		if (string.IsNullOrWhiteSpace(savedPath))
		{
			return fallbackPath;
		}
		try
		{
			string text = savedPath.Trim();
			string baseDirectory = InstallRoot;
			if (text.StartsWith(".\\", StringComparison.Ordinal) || text.StartsWith("./", StringComparison.Ordinal))
			{
				return Path.GetFullPath(Path.Combine(baseDirectory, text.Substring(2)));
			}
			if (!Path.IsPathRooted(text))
			{
				return Path.GetFullPath(Path.Combine(baseDirectory, text));
			}
			return Directory.Exists(text) ? text : fallbackPath;
		}
		catch
		{
			return fallbackPath;
		}
	}

	private string ResolveAudioPathSetting(string savedPath)
	{
		string fallback = GetDefaultAudioPath();
		if (IsDefaultGeneratedAudioPath(savedPath))
		{
			return fallback;
		}
		return ResolvePortablePath(savedPath, fallback);
	}

	private void ResolveStoredVoxReference()
	{
		voxReferencePath = "";
		if (!string.IsNullOrWhiteSpace(voxReferenceId) && Regex.IsMatch(voxReferenceId, "^[0-9a-fA-F]{64}$"))
		{
			string candidate = Path.Combine(GetVoxRoot(), "voices", "user", voxReferenceId.ToLowerInvariant() + ".wav");
			if (File.Exists(candidate))
			{
				voxReferencePath = candidate;
			}
		}
		UpdateVoxReferenceControls();
	}

	private void UpdateVoxReferenceControls()
	{
		if (panelVoxReference == null)
		{
			return;
		}
		bool cloneSelected = (comboBoxVoice?.SelectedItem as VoiceItem)?.VoiceId == "vox_clone";
		bool hasReference = !string.IsNullOrWhiteSpace(voxReferencePath) && File.Exists(voxReferencePath);
		bool canEditReference = !IsSupertonicSelected() && !generationInProgress;
		buttonSelectReferenceWav.Enabled = canEditReference;
		buttonPlayReferenceWav.Enabled = canEditReference && hasReference;
		buttonClearReferenceWav.Enabled = canEditReference && hasReference;
		labelVoxReferenceStatus.ForeColor = cloneSelected && !hasReference ? Color.FromArgb(180, 75, 35) : Color.FromArgb(70, 80, 95);
		if (!hasReference)
		{
			labelVoxReferenceStatus.Text = cloneSelected ? "음성 복제용 WAV를 선택해주세요." : "선택된 참조 WAV 없음 (프리셋은 필요하지 않음)";
			return;
		}
		try
		{
			WavData wav = ReadWavData(File.ReadAllBytes(voxReferencePath));
			double seconds = (double)wav.Data.Length / (wav.SampleRate * wav.Channels * wav.BitsPerSample / 8);
			string displayName = string.IsNullOrWhiteSpace(voxReferenceDisplayName) ? "보관된 참조 WAV" : voxReferenceDisplayName;
			labelVoxReferenceStatus.Text = $"{displayName} · {seconds:0.0}초 · {wav.SampleRate / 1000.0:0.#}kHz 모노";
		}
		catch
		{
			labelVoxReferenceStatus.Text = "참조 WAV를 읽을 수 없습니다.";
		}
	}

	private void buttonSelectReferenceWav_Click(object sender, EventArgs e)
	{
		DialogResult consent = MessageBox.Show(
			"본인 음성이거나 당사자에게 음성 복제와 사용에 대한 명시적 동의를 받은 WAV만 사용할 수 있습니다.\n\n해당 권한과 동의를 확보했습니까?",
			"음성 복제 권한 확인",
			MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning);
		if (consent != DialogResult.Yes)
		{
			return;
		}
		using OpenFileDialog dialog = new OpenFileDialog
		{
			Filter = "WAV 오디오 (*.wav)|*.wav",
			Title = "권한 있는 5~30초 참조 WAV 선택",
			CheckFileExists = true
		};
		if (dialog.ShowDialog() != DialogResult.OK)
		{
			return;
		}
		try
		{
			byte[] normalized = ValidateAndNormalizeReferenceWav(dialog.FileName, out double seconds);
			string hash = Convert.ToHexString(SHA256.HashData(normalized)).ToLowerInvariant();
			string folder = Path.Combine(GetVoxRoot(), "voices", "user");
			Directory.CreateDirectory(folder);
			string target = Path.Combine(folder, hash + ".wav");
			if (!File.Exists(target))
			{
				LocalSidecarSecurity.WriteAllBytesAtomic(target, normalized);
			}
			voxReferenceId = hash;
			voxReferencePath = target;
			voxReferenceDisplayName = Path.GetFileName(dialog.FileName);
			SelectVoiceById("vox_clone");
			UpdateVoxReferenceControls();
			MessageBox.Show($"참조 WAV를 보관했습니다 ({seconds:0.0}초).", "참조 WAV 준비 완료", MessageBoxButtons.OK, MessageBoxIcon.Information);
		}
		catch (Exception ex)
		{
			MessageBox.Show("참조 WAV를 사용할 수 없습니다: " + ex.Message, "WAV 오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	private byte[] ValidateAndNormalizeReferenceWav(string path, out double seconds)
	{
		if (!string.Equals(Path.GetExtension(path), ".wav", StringComparison.OrdinalIgnoreCase))
		{
			throw new Exception("WAV 파일만 지원합니다.");
		}
		long fileSize = new FileInfo(path).Length;
		if (fileSize < 44 || fileSize > LocalSidecarSecurity.ReferenceWavLimitBytes)
		{
			throw new Exception("WAV 파일 크기가 비정상적입니다.");
		}
		WavData wav = ReadWavData(File.ReadAllBytes(path));
		if (wav.AudioFormat != 1 || wav.BitsPerSample != 16 || wav.SampleRate < 8000 || wav.SampleRate > 192000 || wav.Channels < 1 || wav.Channels > 8)
		{
			throw new Exception("PCM16 WAV 형식만 지원합니다.");
		}
		seconds = (double)wav.Data.Length / (wav.SampleRate * wav.Channels * 2);
		if (seconds < 5.0 || seconds > 30.0)
		{
			throw new Exception($"길이가 {seconds:0.0}초입니다. 5~30초 WAV를 선택해주세요.");
		}
		int frames = wav.Data.Length / (2 * wav.Channels);
		byte[] mono = new byte[frames * 2];
		double sumSquares = 0.0;
		for (int frame = 0; frame < frames; frame++)
		{
			long total = 0;
			for (int channel = 0; channel < wav.Channels; channel++)
			{
				total += BitConverter.ToInt16(wav.Data, (frame * wav.Channels + channel) * 2);
			}
			short sample = ClampToShort((double)total / wav.Channels);
			sumSquares += (double)sample * sample;
			BitConverter.GetBytes(sample).CopyTo(mono, frame * 2);
		}
		double rms = Math.Sqrt(sumSquares / Math.Max(1, frames));
		if (rms < 100.0)
		{
			throw new Exception("음성이 거의 들리지 않는 무음 파일입니다.");
		}
		return BuildWav(mono, wav.SampleRate, 1, 16);
	}

	private void buttonPlayReferenceWav_Click(object sender, EventArgs e)
	{
		if (!string.IsNullOrWhiteSpace(voxReferencePath) && File.Exists(voxReferencePath))
		{
			soundPlayer.Stop();
			soundPlayer.SoundLocation = voxReferencePath;
			soundPlayer.Play();
		}
	}

	private void buttonClearReferenceWav_Click(object sender, EventArgs e)
	{
		soundPlayer.Stop();
		voxReferenceId = "";
		voxReferencePath = "";
		voxReferenceDisplayName = "";
		UpdateVoxReferenceControls();
	}

	private string GetDefaultAudioPath()
	{
		string generatedFallback = Path.Combine(InternalRoot, "GeneratedAudio");
		try
		{
			string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
			string downloads = Path.Combine(userProfile, "Downloads");
			if (!string.IsNullOrWhiteSpace(userProfile))
			{
				Directory.CreateDirectory(downloads);
				return downloads;
			}
		}
		catch
		{
		}
		Directory.CreateDirectory(generatedFallback);
		return generatedFallback;
	}

	private bool IsDefaultGeneratedAudioPath(string savedPath)
	{
		if (string.IsNullOrWhiteSpace(savedPath))
		{
			return true;
		}
		try
		{
			string text = savedPath.Trim().Replace('/', '\\');
			if (text.Equals(".\\GeneratedAudio", StringComparison.OrdinalIgnoreCase) ||
				text.Equals("GeneratedAudio", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
			string generated = Path.GetFullPath(Path.Combine(InternalRoot, "GeneratedAudio"));
			string legacyGenerated = Path.GetFullPath(Path.Combine(InstallRoot, "GeneratedAudio"));
			string resolved = Path.GetFullPath(ResolvePortablePath(text, generated)).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			return resolved.Equals(generated.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
				|| resolved.Equals(legacyGenerated.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}

	private string ToPortablePath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return GetDefaultAudioPath();
		}
		try
		{
			string fullPath = Path.GetFullPath(path);
			string text = Path.GetFullPath(InstallRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
			if (fullPath.StartsWith(text, StringComparison.OrdinalIgnoreCase))
			{
				return ".\\" + Path.GetRelativePath(InstallRoot, fullPath);
			}
		}
		catch
		{
		}
		return path;
	}

	private void LoadSavedText()
	{
		try
		{
			string path = Path.Combine(InternalRoot, "SavedText.txt");
			if (File.Exists(path))
			{
				richTextBoxContent.Text = File.ReadAllText(path);
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("저장된 텍스트를 불러오는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void LoadEngineGuide()
	{
		if (IsSupertonicSelected())
		{
			labelGuide.Text = "Supertonic 안내";
			richTextBoxGuide.Text = "Supertonic Local은 PC 안에서 실행됩니다.\n\n- API 키 없이 생성\n- 배속/품질/감정 톤을 오른쪽에서 조절\n- 피치 강제 변조는 음질 보호를 위해 비활성화\n- 긴 글은 자동으로 나눠 자연스럽게 합칩니다.";
		}
		else
		{
			labelGuide.Text = "VoxCPM2 안내";
			richTextBoxGuide.Text = "VoxCPM2 Local은 PC 안에서 오프라인으로 실행됩니다.\n\n- 프리셋은 참조 WAV 없이 사용\n- 내 음성 복제는 권한 있는 5~30초 WAV 필요\n- 고품질 CPU 생성은 한 문장에도 수 분이 걸릴 수 있음\n- 긴 글은 220자 단위로 나눠 자연스럽게 합칩니다.";
		}
	}

	private void Form1_FormClosing(object sender, FormClosingEventArgs e)
	{
		Exception? saveError = null;
		string? shutdownError = null;
		try
		{
			LocalSidecarSecurity.WriteAllTextAtomic(
				Path.Combine(InternalRoot, "SavedText.txt"),
				richTextBoxContent.Text,
				Encoding.UTF8);
		}
		catch (Exception ex)
		{
			saveError = ex;
		}
		finally
		{
			try { soundPlayer.Stop(); } catch { }
			try { generationCancellation?.Cancel(); } catch { }
			try
			{
				if (!StopVoxServer())
				{
					shutdownError = "VoxCPM2 서버 프로세스 트리의 종료를 확인하지 못했습니다. 서버 소유권을 유지하기 위해 프로그램 종료를 취소했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인한 뒤 다시 종료해주세요.";
				}
			}
			catch (Exception ex)
			{
				shutdownError = "VoxCPM2 서버 종료 확인 중 오류가 발생했습니다: " + ex.Message;
			}
			try { StopSupertonicServer(); } catch { }
		}
		if (shutdownError != null)
		{
			e.Cancel = true;
			MessageBox.Show(shutdownError, "VoxCPM2 종료 확인 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		if (saveError != null)
		{
			MessageBox.Show("텍스트를 저장하는 중 오류가 발생했습니다: " + saveError.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void buttonLoadFile_Click(object sender, EventArgs e)
	{
		OpenFileDialog openFileDialog = new OpenFileDialog();
		openFileDialog.Filter = "텍스트 파일 (*.txt)|*.txt|HTML 파일 (*.html;*.htm)|*.html;*.htm|모든 파일 (*.*)|*.*";
		openFileDialog.Title = "파일 불러오기";
		if (openFileDialog.ShowDialog() != DialogResult.OK)
		{
			return;
		}
		try
		{
			string fileName = openFileDialog.FileName;
			string text = Path.GetExtension(fileName).ToLower();
			if (text == ".html" || text == ".htm")
			{
				HtmlAgilityPack.HtmlDocument htmlDocument = new HtmlAgilityPack.HtmlDocument();
				htmlDocument.Load(fileName, Encoding.UTF8);
				richTextBoxContent.Text = htmlDocument.DocumentNode.InnerText;
			}
			else
			{
				richTextBoxContent.Text = File.ReadAllText(fileName, Encoding.UTF8);
			}
		}
		catch (Exception ex)
		{
			MessageBox.Show("파일을 불러오는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private async void buttonGenerateAudio_Click(object sender, EventArgs e)
	{
		string text = richTextBoxContent.Text;
		if (string.IsNullOrEmpty(text))
		{
			MessageBox.Show("음성으로 변환할 텍스트가 없습니다.", "경고", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		string title = textBoxTitle.Text;
		if (string.IsNullOrWhiteSpace(title))
		{
			MessageBox.Show("음성 파일의 제목을 입력해주세요.", "경고", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		title = title.Trim();
		string? titleError = GetOutputTitleError(title);
		if (titleError != null)
		{
			MessageBox.Show(titleError, "파일 제목 오류", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		if (IsSupertonicSelected())
		{
			await GenerateAndPlaySupertonicAudio(title, text);
			return;
		}
		if (text.Length > 5000)
		{
			MessageBox.Show("VoxCPM2는 한 번에 최대 5,000자까지 생성할 수 있습니다.", "텍스트가 너무 깁니다", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		if (text.Length > 1000 && MessageBox.Show("1,000자를 넘는 고품질 CPU 생성은 매우 오래 걸릴 수 있습니다. 계속할까요?", "장시간 생성 안내", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
		{
			return;
		}
		VoiceItem selectedVoice = comboBoxVoice.SelectedItem as VoiceItem;
		if (selectedVoice?.VoiceId == "vox_clone" && (string.IsNullOrWhiteSpace(voxReferencePath) || !File.Exists(voxReferencePath)))
		{
			MessageBox.Show("내 WAV 음성 복제를 사용하려면 5~30초 참조 WAV를 먼저 선택해주세요.", "참조 WAV 필요", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		await GenerateAndPlayVoxAudio(title, text);
	}

	private async Task GenerateAndPlayVoxAudio(string title, string text)
	{
		VoxGenerationSnapshot snapshot;
		try
		{
			snapshot = CaptureVoxGenerationSnapshot(title, text);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "VoxCPM2 설정 오류", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		generationCancellation?.Dispose();
		generationCancellation = new CancellationTokenSource();
		CancellationToken cancellationToken = generationCancellation.Token;
		generationInProgress = true;
		SetVoxGenerationControlsLocked(true);
		buttonPlayGenerated.Enabled = false;
		buttonStopGenerated.Enabled = true;
		buttonStopGenerated.Text = "생성 취소";
		progressBarTts.Style = ProgressBarStyle.Marquee;
		string partialPath = "";
		try
		{
			labelProgressStatus.Text = "VoxCPM2 CPU 모델 준비 중...";
			await EnsureVoxServerAsync();
			cancellationToken.ThrowIfCancellationRequested();
			string prepared = PrepareTextForVox(snapshot.Text);
			List<string> chunks = SplitTextIntoChunks(prepared, VoxMaxChunkLength);
			if (chunks.Count == 0)
			{
				throw new Exception("전처리 후 생성할 텍스트가 없습니다.");
			}
			List<byte[]> wavFiles = new List<byte[]>();
			for (int i = 0; i < chunks.Count; i++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				buttonGenerateAudio.Text = $"Vox 생성 중... ({i + 1}/{chunks.Count})";
				labelProgressStatus.Text = $"VoxCPM2 생성 중... ({i + 1}/{chunks.Count})";
				byte[] wav;
				try
				{
					wav = await CallVoxTtsApi(chunks[i], snapshot.ProfileId, snapshot.ReferencePath, snapshot.InferenceSteps, snapshot.Seed, cancellationToken);
				}
				catch (TimeoutException ex) when (!cancellationToken.IsCancellationRequested)
				{
					throw new VoxChunkTimeoutException(i + 1, chunks.Count, ex);
				}
				cancellationToken.ThrowIfCancellationRequested();
				ValidateVoxOutput(wav);
				wavFiles.Add(wav);
			}
			cancellationToken.ThrowIfCancellationRequested();
			byte[] bytes = MergeWavFilesWithSilence(wavFiles, snapshot.SilenceSeconds);
			if (Math.Abs(snapshot.SpeedFactor - 1.0) >= 0.01 || Math.Abs(snapshot.VolumeFactor - 1.0) >= 0.01)
			{
				labelProgressStatus.Text = "배속/볼륨 적용 중...";
				bytes = ApplyVoicePostProcessingToWav(bytes, snapshot.SpeedFactor, 0, snapshot.VolumeFactor);
			}
			cancellationToken.ThrowIfCancellationRequested();
			Directory.CreateDirectory(snapshot.OutputDirectory);
			string outputPath = LocalSidecarSecurity.CreateUniqueOutputPath(snapshot.OutputDirectory, snapshot.Title);
			partialPath = outputPath + ".partial";
			LocalSidecarSecurity.WriteAllBytesAtomic(outputPath, bytes);
			partialPath = "";
			SetLastGeneratedAudio(outputPath, autoPlay: true);
			MessageBox.Show("음성 파일이 성공적으로 생성되어 '" + outputPath + "'에 저장되었습니다.", "완료", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			labelProgressStatus.Text = "VoxCPM2 생성이 취소되었습니다.";
		}
		catch (VoxChunkTimeoutException ex)
		{
			if (!StopVoxServer())
			{
				MessageBox.Show("시간 초과 후 VoxCPM2 서버 프로세스 트리의 종료를 재확인하지 못했습니다. 소유권과 뮤텍스는 유지했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.", "VoxCPM2 종료 확인 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			if (!string.IsNullOrWhiteSpace(partialPath) && File.Exists(partialPath))
			{
				try { File.Delete(partialPath); } catch { }
				partialPath = "";
			}
			MessageBox.Show(ex.Message, "VoxCPM2 조각 생성 시간 초과", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		catch (Exception ex)
		{
			string text2 = ex.Message;
			if (ex.InnerException != null && !string.IsNullOrWhiteSpace(ex.InnerException.Message))
			{
				text2 = text2 + "\n" + ex.InnerException.Message;
			}
			MessageBox.Show("오류가 발생했습니다: " + text2, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
		finally
		{
			if (!string.IsNullOrWhiteSpace(partialPath) && File.Exists(partialPath))
			{
				try { File.Delete(partialPath); } catch { }
			}
			generationInProgress = false;
			generationCancellation?.Dispose();
			generationCancellation = null;
			SetVoxGenerationControlsLocked(false);
			UpdateModelStatusLabel();
			buttonGenerateAudio.Text = "음성 생성";
			buttonStopGenerated.Text = "정지";
			progressBarTts.Style = ProgressBarStyle.Blocks;
			labelProgressStatus.Text = "";
			buttonPlayGenerated.Enabled = !string.IsNullOrWhiteSpace(lastGeneratedAudioPath) && File.Exists(lastGeneratedAudioPath);
			buttonStopGenerated.Enabled = buttonPlayGenerated.Enabled;
		}
	}

	private async Task GenerateAndPlaySupertonicAudio(string title, string text)
	{
		buttonGenerateAudio.Enabled = false;
		buttonPlayGenerated.Enabled = false;
		buttonStopGenerated.Enabled = false;
		progressBarTts.Style = ProgressBarStyle.Marquee;
		labelProgressStatus.Text = "Supertonic 로컬 엔진 준비 중...";
		try
		{
			await EnsureSupertonicServerAsync();
			string voiceName = ((VoiceItem)comboBoxVoice.SelectedItem).VoiceId;
			double speed = GetSelectedSpeed();
			int steps = GetSelectedSteps();
			int pitchSemitones = 0;
			double volumeFactor = GetSelectedVolumeFactor();
			double silenceDuration = GetSelectedSilenceDuration();
			string text2 = PrepareTextForSupertonic(text);
			byte[] array;
			if (text2.Length > 20000)
			{
				List<string> chunks = SplitTextIntoChunks(text2, 10000);
				List<byte[]> wavFiles = new List<byte[]>();
				for (int i = 0; i < chunks.Count; i++)
				{
					buttonGenerateAudio.Text = $"로컬 생성 중... ({i + 1}/{chunks.Count})";
					labelProgressStatus.Text = $"Supertonic 생성 중... ({i + 1}/{chunks.Count})";
					List<byte[]> list = wavFiles;
					list.Add(await CallSupertonicTtsApi(chunks[i], voiceName, 1.0, steps, silenceDuration));
				}
				array = MergeWavFiles(wavFiles);
			}
			else
			{
				buttonGenerateAudio.Text = "로컬 생성 중...";
				labelProgressStatus.Text = "Supertonic 생성 중...";
				array = await CallSupertonicTtsApi(text2, voiceName, 1.0, steps, silenceDuration);
			}
			if (Math.Abs(speed - 1.0) >= 0.01 || pitchSemitones != 0 || Math.Abs(volumeFactor - 1.0) >= 0.01)
			{
				buttonGenerateAudio.Text = "톤 보정 중...";
				labelProgressStatus.Text = "배속/볼륨 적용 중...";
				array = ApplyVoicePostProcessingToWav(array, speed, pitchSemitones, volumeFactor);
			}
			string text3 = LocalSidecarSecurity.CreateUniqueOutputPath(savedAudioPath, title);
			LocalSidecarSecurity.WriteAllBytesAtomic(text3, array);
			SetLastGeneratedAudio(text3, autoPlay: true);
			MessageBox.Show("음성 파일이 성공적으로 생성되어 '" + text3 + "'에 저장되었습니다.", "완료", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
		}
		catch (Exception ex)
		{
			string text4 = ex.Message;
			if (ex.InnerException != null && !string.IsNullOrWhiteSpace(ex.InnerException.Message))
			{
				text4 = text4 + "\n" + ex.InnerException.Message;
			}
			MessageBox.Show("오류가 발생했습니다: " + text4, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
		finally
		{
			buttonGenerateAudio.Enabled = true;
			buttonGenerateAudio.Text = "음성 생성";
			progressBarTts.Style = ProgressBarStyle.Blocks;
			labelProgressStatus.Text = "";
			buttonPlayGenerated.Enabled = !string.IsNullOrWhiteSpace(lastGeneratedAudioPath) && File.Exists(lastGeneratedAudioPath);
			buttonStopGenerated.Enabled = buttonPlayGenerated.Enabled;
		}
	}

	private double GetSelectedSpeed()
	{
		return (double)(trackBarSpeed?.Value ?? (IsSupertonicSelected() ? 105 : 100)) / 100.0;
	}

	private string? GetOutputTitleError(string title)
	{
		if (title.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
		{
			return "파일 제목에 사용할 수 없는 문자가 있습니다: \\ / : * ? \" < > |";
		}
		if (title.EndsWith(' ') || title.EndsWith('.'))
		{
			return "파일 제목은 공백이나 마침표로 끝날 수 없습니다.";
		}
		try
		{
			string candidate = Path.GetFullPath(Path.Combine(savedAudioPath, $"{DateTime.Now:yyyyMMdd_HHmmss}_{title}.wav"));
			if (candidate.Length >= 240)
			{
				return "저장 경로와 파일 제목이 너무 깁니다. 제목을 짧게 입력해주세요.";
			}
		}
		catch (Exception)
		{
			return "저장 경로나 파일 제목이 올바르지 않습니다.";
		}
		return null;
	}

	private VoxGenerationSnapshot CaptureVoxGenerationSnapshot(string title, string text)
	{
		VoiceItem voice = comboBoxVoice.SelectedItem as VoiceItem ?? new VoiceItem("vox_news_f", "뉴스 여성");
		bool clone = string.Equals(voice.VoiceId, "vox_clone", StringComparison.Ordinal);
		string? referencePath = clone ? voxReferencePath : null;
		if (clone && (string.IsNullOrWhiteSpace(referencePath) || !File.Exists(referencePath)))
		{
			throw new InvalidOperationException("내 WAV 음성 복제에는 유효한 5~30초 참조 WAV가 필요합니다.");
		}

		string quality = comboBoxQuality?.SelectedItem?.ToString() ?? "고품질";
		int inferenceSteps = quality == "빠른 생성" ? 6 : quality == "고품질" ? 10 : 8;
		return new VoxGenerationSnapshot(
			title,
			text,
			savedAudioPath,
			voice.VoiceId,
			referencePath,
			inferenceSteps,
			(double)(trackBarSpeed?.Value ?? 100) / 100.0,
			(double)(trackBarVolume?.Value ?? 100) / 100.0,
			(double)(trackBarPause?.Value ?? 25) / 100.0,
			42);
	}

	private void SetVoxGenerationControlsLocked(bool locked)
	{
		bool enabled = !locked;
		richTextBoxContent.ReadOnly = locked;
		textBoxTitle.ReadOnly = locked;
		comboBoxEngine.Enabled = enabled;
		comboBoxVoice.Enabled = enabled;
		comboBoxQuality.Enabled = enabled;
		trackBarSpeed.Enabled = enabled;
		trackBarVolume.Enabled = enabled;
		trackBarPause.Enabled = enabled;
		buttonLoadFile.Enabled = enabled;
		buttonSelectFolder.Enabled = enabled;
		buttonSaveSettings.Enabled = enabled;
		buttonPlaySample.Enabled = enabled;
		buttonGenerateAudio.Enabled = enabled;
		if (locked)
		{
			buttonSelectReferenceWav.Enabled = false;
			buttonPlayReferenceWav.Enabled = false;
			buttonClearReferenceWav.Enabled = false;
		}
		else
		{
			UpdateVoxReferenceControls();
		}
	}

	private int GetSelectedSteps()
	{
		string text = comboBoxQuality?.SelectedItem?.ToString() ?? "균형";
		if (text == "빠른 생성")
		{
			return IsSupertonicSelected() ? 5 : 6;
		}
		if (text == "고품질")
		{
			return 10;
		}
		return 8;
	}

	private int GetSelectedPitchSemitones()
	{
		return 0;
	}

	private double GetSelectedVolumeFactor()
	{
		return (double)(trackBarVolume?.Value ?? 100) / 100.0;
	}

	private double GetSelectedSilenceDuration()
	{
		return (double)(trackBarPause?.Value ?? 25) / 100.0;
	}

	private string GetSelectedTonePreset()
	{
		return comboBoxTonePreset?.SelectedItem?.ToString() ?? "기본";
	}

	private bool IsSibilantRescueEnabled
	{
		get
		{
			return checkBoxSibilantRescue == null || checkBoxSibilantRescue.Checked;
		}
	}

	private PronunciationEngine.SibilantMode SelectedSibilantMode
	{
		get
		{
			if (!IsSibilantRescueEnabled)
			{
				return PronunciationEngine.SibilantMode.Off;
			}
			return PronunciationEngine.SupertonicSibilantRescueNormalizer.ParseMode(comboBoxSibilantMode?.SelectedItem?.ToString() ?? "기본");
		}
	}

	private void UpdateSibilantDebugButton()
	{
		if (buttonSibilantDebug == null)
		{
			return;
		}
		buttonSibilantDebug.Enabled = IsSupertonicSelected() && IsSibilantRescueEnabled && SelectedSibilantMode == PronunciationEngine.SibilantMode.Debug;
		buttonSibilantDebug.Visible = IsSupertonicSelected() && IsSibilantRescueEnabled && SelectedSibilantMode == PronunciationEngine.SibilantMode.Debug;
	}

	private string NormalizeTextForSupertonic(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return "";
		}
		RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Singleline;
		return Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(text.Replace("\r\n", "\n").Replace('\r', '\n'), "<\\s*/?\\s*speak\\s*>", "", options), "<\\s*break\\b[^>]*\\/?\\s*>", "\n\n", options), "<\\s*emphasis\\b[^>]*>(.*?)<\\s*/\\s*emphasis\\s*>", "$1", options), "<\\s*say-as\\b[^>]*interpret-as\\s*=\\s*[\"']characters[\"'][^>]*>(.*?)<\\s*/\\s*say-as\\s*>", (Match m) => string.Join(" ", m.Groups[1].Value.Where((char c) => !char.IsWhiteSpace(c))), options), "<\\s*prosody\\b[^>]*>(.*?)(?:<\\s*/\\s*prosody\\s*>|<\\s*prosody\\s*>)", "$1", options), "<[^>]+>", "", options), "[ \\t]{2,}", " "), "\\n{3,}", "\n\n").Trim();
	}

	private string PrepareTextForVox(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return "";
		}
		RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Singleline;
		string clean = text.Replace("\r\n", "\n").Replace('\r', '\n');
		clean = Regex.Replace(clean, "<\\s*break\\b[^>]*\\/?\\s*>", ". ", options);
		clean = Regex.Replace(clean, "<[^>]+>", "", options);
		clean = WebUtility.HtmlDecode(clean);
		clean = Regex.Replace(clean, "[ \\t]{2,}", " ");
		clean = Regex.Replace(clean, "\\n{3,}", "\n\n").Trim();
		if (string.IsNullOrWhiteSpace(clean))
		{
			return "";
		}
		string prepared = PronunciationEngine.KoreanNumberReader.Expand(clean);
		prepared = PronunciationEngine.DictionaryRewriter.ApplyAcronyms(prepared, InternalRoot);
		prepared = PronunciationEngine.DictionaryRewriter.ApplyUserOverrides(prepared, InternalRoot);
		prepared = Regex.Replace(prepared, "[ \\t]{2,}", " ");
		return Regex.Replace(prepared, "\\n{3,}", "\n\n").Trim();
	}

	private string PrepareTextForSupertonic(string text)
	{
		return PreparePronunciationResult(text).TtsRequestText;
	}

	private PronunciationEngine.PronunciationResult PreparePronunciationResult(string text)
	{
		var baseResult = PrepareBasePronunciationResult(text);
		if (string.IsNullOrWhiteSpace(baseResult.TtsRequestText))
		{
			return baseResult;
		}
		var voice = (comboBoxVoice?.SelectedItem as VoiceItem)?.VoiceId ?? "M1";
		var rescue = PronunciationEngine.SupertonicSibilantRescueNormalizer.Normalize(
			baseResult.TtsRequestText,
			voice,
			SelectedSibilantMode,
			new PronunciationEngine.SibilantRewriteOptions
			{
				BaseDirectory = InternalRoot,
				Enabled = IsSibilantRescueEnabled
			});
		var rules = baseResult.RulesApplied
			.Concat(rescue.AppliedRuleIds.Select(id => $"{id} (risk {rescue.RiskScore})"))
			.ToArray();
		string ttsText = rescue.TtsText;
		if (IsCourtPleadingToneSelected())
		{
			string beforeCourt = ttsText;
			ttsText = ApplyCourtPleadingStyle(ttsText);
			if (!string.Equals(beforeCourt, ttsText, StringComparison.Ordinal))
			{
				rules = rules.Concat(new[] { "COURT_PLEADING_STYLE" }).ToArray();
			}
		}
		return baseResult with { TtsRequestText = ttsText, RulesApplied = rules };
	}

	private bool IsCourtPleadingToneSelected()
	{
		return string.Equals(GetSelectedTonePreset(), TonePresetCourtPleading, StringComparison.Ordinal);
	}

	private string ApplyCourtPleadingStyle(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return "";
		}
		string result = text.Replace("\r\n", "\n").Replace('\r', '\n');
		result = Regex.Replace(result, @"[ \t]+", " ");
		result = Regex.Replace(result, @"\s*!\s*(?:!\s*)+", "! ");
		result = Regex.Replace(result, @"\s*\?\s*(?:\?\s*)+", "? ");
		result = Regex.Replace(result, @"\n{2,}", ". ");
		result = Regex.Replace(result, @"\n+", " ");
		result = Regex.Replace(result, @"([!?])\s*\.\s*", "$1 ");
		result = Regex.Replace(result, @"\.\s*([!?])", "$1");
		result = Regex.Replace(result, @"(?:이의|이이)\s+있(?:습|씀|슴)니다\s*[.!?]*", "이이 있씀니다!");
		result = Regex.Replace(result, @"(?<![가-힣])피고는\s*,?\s*", "피고는, ");
		result = Regex.Replace(result, @"오슬\s+못\s+입는게", "오슬 못 입는 게");
		result = Regex.Replace(result, @"옷을\s+못\s+입는게", "오슬 못 입는 게");
		result = Regex.Replace(result, @"오슬\s+못\s+입는\s+게\s+아니라\s*", "오슬 못 입는 게 아니라, ");
		result = Regex.Replace(result, @"옷을\s+못\s+입는\s+게\s+아니라\s*", "오슬 못 입는 게 아니라, ");
		result = Regex.Replace(result, @"무신사를\s+몰랐을\s+뿐(?:입|임)니다\s*[.!?]*", "무신사를 몰랐을 뿐임니다!");
		result = Regex.Replace(result, @",\s*,+", ", ");
		result = Regex.Replace(result, @"\s+([,.?!])", "$1");
		result = Regex.Replace(result, @"([,.?!])(?=\S)", "$1 ");
		result = Regex.Replace(result, @"[ \t]{2,}", " ");
		return result.Trim();
	}

	private PronunciationEngine.PronunciationResult PrepareBasePronunciationResult(string text)
	{
		string text2 = NormalizeTextForSupertonic(text);
		if (string.IsNullOrWhiteSpace(text2))
		{
			return new PronunciationEngine.PronunciationResult(text ?? "", "", "", Array.Empty<string>());
		}
		return PronunciationEngine.KoreanAnnouncerPronunciationNormalizer.NormalizeForTts(text2, new PronunciationEngine.PronunciationOptions
		{
			BaseDirectory = InternalRoot,
			ApplyNumberReading = true,
			ApplyAcronymReading = true,
			ApplyUserOverrides = true,
			ApplySibilantSafeRewrite = true,
			ApplyAnnouncerPauses = true
		});
	}

	private string ApplyPronunciationOverrides(string text)
	{
		foreach (PronunciationRule item in LoadPronunciationOverrides().Where((PronunciationRule r) => !string.IsNullOrWhiteSpace(r.From)).OrderByDescending((PronunciationRule r) => r.From.Length))
		{
			if (!string.IsNullOrWhiteSpace(item.To))
			{
				text = text.Replace(item.From, item.To, StringComparison.Ordinal);
			}
		}
		return text;
	}

	private List<PronunciationRule> LoadPronunciationOverrides()
	{
		if (!File.Exists(pronunciationOverridesPath))
		{
			List<PronunciationRule> list = DefaultPronunciationRules();
			WriteDefaultPronunciationOverrides(list);
			return list;
		}
		try
		{
			JArray jArray = JArray.Parse(File.ReadAllText(pronunciationOverridesPath, Encoding.UTF8));
			return jArray.Select((JToken token) => new PronunciationRule(token["From"]?.ToString() ?? token["from"]?.ToString() ?? "", token["To"]?.ToString() ?? token["to"]?.ToString() ?? "", token["Note"]?.ToString() ?? token["note"]?.ToString() ?? "")).ToList();
		}
		catch
		{
			return DefaultPronunciationRules();
		}
	}

	private void WriteDefaultPronunciationOverrides(List<PronunciationRule> rules)
	{
		try
		{
			JArray jArray = new JArray();
			foreach (PronunciationRule rule in rules)
			{
				jArray.Add(new JObject
				{
					["From"] = rule.From,
					["To"] = rule.To,
					["Note"] = rule.Note
				});
			}
			File.WriteAllText(pronunciationOverridesPath, jArray.ToString(), Encoding.UTF8);
		}
		catch
		{
		}
	}

	private List<PronunciationRule> DefaultPronunciationRules()
	{
		return new List<PronunciationRule>
		{
			new PronunciationRule("아시나요?", "아씨나요?", "시나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("아시나요", "아씨나요", "시나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("하시나요?", "하씨나요?", "시나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("하시나요", "하씨나요", "시나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("계셨나요?", "계셧나요?", "셨나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("계셨나요", "계셧나요", "셨나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("하셨나요?", "하셧나요?", "셨나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("하셨나요", "하셧나요", "셨나요 계열의 영어식 굴림 완화"),
			new PronunciationRule("흔들 수 있습니다", "흔들 수 있씀니다", "수/습니다 연결부의 굴림 완화"),
			new PronunciationRule("할 수 있습니다", "할 수 있씀니다", "수/습니다 연결부의 굴림 완화"),
			new PronunciationRule("수 있습니다", "수 있씀니다", "수/습니다 연결부의 굴림 완화"),
			new PronunciationRule("있습니다", "있씀니다", "습니다 종결부를 더 안정적으로 유도"),
			new PronunciationRule("있어요", "이써요", "있어요의 ㅅ 굴림 완화"),
			new PronunciationRule("하셨어요", "하셔써요", "셨어요 계열의 ㅅ 굴림 완화"),
			new PronunciationRule("했습니다", "했씀니다", "습니다 종결부를 더 안정적으로 유도"),
			new PronunciationRule("됩니다", "됨니다", "ㅂ니다 종결부를 더 안정적으로 유도")
		};
	}

	private string ApplySibilantStabilization(string text)
	{
		text = Regex.Replace(text, "(?<![가-힣])수\\s+있습니다(?![가-힣])", "수 있씀니다");
		text = Regex.Replace(text, "(?<![가-힣])수\\s+있어요(?![가-힣])", "수 이써요");
		text = Regex.Replace(text, "(?<=[가-힣])시나요", "씨나요");
		text = Regex.Replace(text, "(?<=[가-힣])셨나요", "셧나요");
		text = Regex.Replace(text, "(?<=[가-힣])실까요", "씰까요");
		text = text.Replace("하셨어요", "하셔써요", StringComparison.Ordinal);
		text = text.Replace("있습니다", "있씀니다", StringComparison.Ordinal);
		text = text.Replace("있어요", "이써요", StringComparison.Ordinal);
		text = text.Replace("했습니다", "했씀니다", StringComparison.Ordinal);
		text = text.Replace("었습니다", "었씀니다", StringComparison.Ordinal);
		text = text.Replace("았습니다", "았씀니다", StringComparison.Ordinal);
		text = text.Replace("겠습니다", "겠씀니다", StringComparison.Ordinal);
		text = text.Replace("되었습니다", "되었씀니다", StringComparison.Ordinal);
		text = text.Replace("됩니다", "됨니다", StringComparison.Ordinal);
		text = Regex.Replace(text, "(?<![가-힣])습니다\\b", "씀니다");
		text = Regex.Replace(text, "(?<=[가-힣])습니다\\b", "씀니다");
		text = Regex.Replace(text, "[ \\t]{2,}", " ");
		return text.Trim();
	}

	private static class KoreanNumberPronunciationNormalizer
	{
		private const string ParticlePattern = "((?:에서|부터|까지|은|는|이|가|을|를|에|쯤|경|만|도){0,2})";

		private static readonly string[] SinoDigits = new string[10] { "영", "일", "이", "삼", "사", "오", "육", "칠", "팔", "구" };

		private static readonly string[] SmallUnits = new string[4] { "", "십", "백", "천" };

		private static readonly string[] LargeUnits = new string[5] { "", "만", "억", "조", "경" };

		private static readonly string[] NativeOnes = new string[10] { "", "한", "두", "세", "네", "다섯", "여섯", "일곱", "여덟", "아홉" };

		private static readonly string[] NativeTeens = new string[11] { "", "열", "열한", "열두", "열세", "열네", "열다섯", "열여섯", "열일곱", "열여덟", "열아홉" };

		private static readonly string[] NativeTens = new string[10] { "", "", "스물", "서른", "마흔", "쉰", "예순", "일흔", "여든", "아흔" };

		private static readonly string[] NativeHours = new string[13] { "", "한", "두", "세", "네", "다섯", "여섯", "일곱", "여덟", "아홉", "열", "열한", "열두" };

		public static string Apply(string text)
		{
			if (string.IsNullOrWhiteSpace(text))
			{
				return "";
			}
			Dictionary<string, string> protectedTokens = new Dictionary<string, string>();
			text = ProtectCodeTokens(text, protectedTokens);
			text = Regex.Replace(text, "(?<!\\d)(0\\d{1,2})[-\\s](\\d{3,4})[-\\s](\\d{4})(?!\\d)", (Match m) => ReadDigits(m.Groups[1].Value) + ", " + ReadDigits(m.Groups[2].Value) + ", " + ReadDigits(m.Groups[3].Value));
			text = Regex.Replace(text, "(?<![A-Za-z0-9가-힣])\\$(\\d[\\d,]*(?:\\.\\d+)?)", (Match m) => ReadNumber(m.Groups[1].Value) + " 달러");
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*(?:\\.\\d+)?)\\s*(%|퍼센트)" + ParticlePattern, (Match m) => ReadNumber(m.Groups[1].Value) + " 퍼센트" + m.Groups[3].Value);
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d{1,2})\\s*:\\s*(\\d{2})" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadHour(m.Groups[1].Value) + "시 " + ReadNumber(m.Groups[2].Value) + "분" + m.Groups[3].Value);
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d{1,2})\\s*시\\s*(\\d{1,2})\\s*분?" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadHour(m.Groups[1].Value) + "시 " + ReadNumber(m.Groups[2].Value) + "분" + m.Groups[3].Value);
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d{1,2})\\s*시" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadHour(m.Groups[1].Value) + "시" + m.Groups[2].Value);
			text = ReplaceNativeRange(text);
			text = ReplaceSinoRange(text);
			text = Regex.Replace(text, "제\\s*(\\d[\\d,]*)\\s*(장|회|차|부|편|번)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => "제" + ReadNumber(m.Groups[1].Value) + m.Groups[2].Value + m.Groups[3].Value);
			text = ReplaceNativeUnit(text);
			text = ReplaceSinoUnit(text, "년|월|일|분|초|원|층|쪽|페이지|번|차|회|위|등");
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*(?:\\.\\d+)?)\\s*(달러)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadNumber(m.Groups[1].Value) + " 달러" + m.Groups[3].Value);
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*(?:\\.\\d+)?)(?![A-Za-z0-9])", (Match m) => ReadNumber(m.Groups[1].Value));
			text = RestoreCodeTokens(text, protectedTokens);
			text = Regex.Replace(text, "[ \\t]{2,}", " ");
			return text.Trim();
		}

		private static string ProtectCodeTokens(string text, Dictionary<string, string> protectedTokens)
		{
			return Regex.Replace(text, "https?://\\S+|www\\.\\S+|[A-Za-z가-힣0-9_\\-]+\\.[A-Za-z]{1,5}\\b|\\b[vV]\\d+(?:\\.\\d+)+\\b|\\b[A-Za-z]+[-_]?\\d+(?:\\.\\d+)*\\b", delegate(Match m)
			{
				string text2 = ((char)(57344 + protectedTokens.Count)).ToString();
				protectedTokens[text2] = m.Value;
				return text2;
			});
		}

		private static string RestoreCodeTokens(string text, Dictionary<string, string> protectedTokens)
		{
			foreach (KeyValuePair<string, string> protectedToken in protectedTokens)
			{
				text = text.Replace(protectedToken.Key, protectedToken.Value, StringComparison.Ordinal);
			}
			return text;
		}

		private static string ReplaceNativeRange(string text)
		{
			return Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*)\\s*(?:~|-|–|—)\\s*(\\d[\\d,]*)\\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadNativeCount(m.Groups[1].Value) + " " + m.Groups[3].Value + "에서 " + ReadNativeCount(m.Groups[2].Value) + " " + m.Groups[3].Value + m.Groups[4].Value);
		}

		private static string ReplaceSinoRange(string text)
		{
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*)\\s*(?:~|-|–|—)\\s*(\\d[\\d,]*)\\s*(년|월|일|분|초|원|층|쪽|페이지|번|차|회|위|등)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadUnitNumber(m.Groups[1].Value, m.Groups[3].Value) + m.Groups[3].Value + "에서 " + ReadUnitNumber(m.Groups[2].Value, m.Groups[3].Value) + m.Groups[3].Value + m.Groups[4].Value);
			return Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*)\\s*(?:~|-|–|—)\\s*(\\d[\\d,]*)(?![A-Za-z0-9가-힣])", (Match m) => ReadNumber(m.Groups[1].Value) + "에서 " + ReadNumber(m.Groups[2].Value));
		}

		private static string ReplaceNativeUnit(string text)
		{
			text = Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*\\.\\d+)\\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadNumber(m.Groups[1].Value) + " " + m.Groups[2].Value + m.Groups[3].Value);
			return Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*)\\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadNativeCount(m.Groups[1].Value) + " " + m.Groups[2].Value + m.Groups[3].Value);
		}

		private static string ReplaceSinoUnit(string text, string unitPattern)
		{
			return Regex.Replace(text, "(?<![A-Za-z0-9])(\\d[\\d,]*(?:\\.\\d+)?)\\s*(" + unitPattern + ")" + ParticlePattern + "(?![A-Za-z0-9가-힣])", (Match m) => ReadUnitNumber(m.Groups[1].Value, m.Groups[2].Value) + m.Groups[2].Value + m.Groups[3].Value);
		}

		private static string ReadUnitNumber(string raw, string unit)
		{
			if (unit == "월")
			{
				int month;
				if (int.TryParse(raw.Replace(",", ""), out month))
				{
					if (month == 6)
					{
						return "유";
					}
					if (month == 10)
					{
						return "시";
					}
				}
			}
			return ReadNumber(raw);
		}

		private static string ReadHour(string raw)
		{
			int hour;
			if (int.TryParse(raw, out hour) && hour >= 1 && hour < NativeHours.Length)
			{
				return NativeHours[hour];
			}
			return ReadNumber(raw);
		}

		private static string ReadNativeCount(string raw)
		{
			string text = raw.Replace(",", "");
			int value;
			if (!int.TryParse(text, out value) || value <= 0)
			{
				return ReadNumber(raw);
			}
			if (value < 10)
			{
				return NativeOnes[value];
			}
			if (value < 20)
			{
				return NativeTeens[value - 9];
			}
			if (value < 100)
			{
				int num = value / 10;
				int num2 = value % 10;
				if (num == 2 && num2 == 0)
				{
					return "스무";
				}
				return NativeTens[num] + ((num2 > 0) ? NativeOnes[num2] : "");
			}
			return ReadNumber(raw);
		}

		private static string ReadNumber(string raw)
		{
			string text = raw.Replace(",", "").Trim();
			if (text.Length == 0)
			{
				return raw;
			}
			if (text.Contains("."))
			{
				string[] array = text.Split(new char[1] { '.' }, 2);
				string text2 = ReadInteger(array[0]);
				string text3 = (array.Length > 1) ? ReadDigits(array[1]) : "";
				if (string.IsNullOrWhiteSpace(text3))
				{
					return text2;
				}
				return text2 + " 점 " + text3;
			}
			if (text.Length > 1 && text.StartsWith("0", StringComparison.Ordinal))
			{
				return ReadDigits(text);
			}
			return ReadInteger(text);
		}

		private static string ReadDigits(string digits)
		{
			List<string> list = new List<string>();
			foreach (char item in digits.Where(char.IsDigit))
			{
				list.Add((item == '0') ? "공" : SinoDigits[item - 48]);
			}
			return string.Join(" ", list);
		}

		private static string ReadInteger(string digits)
		{
			digits = digits.TrimStart('0');
			if (digits.Length == 0)
			{
				return "영";
			}
			List<string> list = new List<string>();
			int num = 0;
			for (int num2 = digits.Length; num2 > 0; num2 -= 4)
			{
				int num3 = Math.Max(0, num2 - 4);
				string s = digits.Substring(num3, num2 - num3);
				int num4 = int.Parse(s);
				if (num4 > 0)
				{
					string text = ReadFourDigits(num4);
					string str = (num < LargeUnits.Length) ? LargeUnits[num] : "";
					if (num4 == 1 && num > 0)
					{
						text = "";
					}
					list.Insert(0, text + str);
				}
				num++;
			}
			return string.Join("", list);
		}

		private static string ReadFourDigits(int value)
		{
			StringBuilder stringBuilder = new StringBuilder();
			string text = value.ToString("D4");
			for (int i = 0; i < 4; i++)
			{
				int num = text[i] - 48;
				int num2 = 3 - i;
				if (num != 0)
				{
					if (num != 1 || num2 <= 0)
					{
						stringBuilder.Append(SinoDigits[num]);
					}
					stringBuilder.Append(SmallUnits[num2]);
				}
			}
			return stringBuilder.ToString();
		}
	}

	private string PronunciationCacheToken()
	{
		string text = IsSupertonicSelected()
			? "tts-ko-read-v10-court|" + GetSelectedTonePreset() + "|" + IsSibilantRescueEnabled + "|" + SelectedSibilantMode + "|" + PrepareTextForSupertonic("샘플 음성입니다. 안녕하세요")
			: "vox-ko-read-v1|" + PrepareTextForVox("샘플 음성입니다. 안녕하세요");
		unchecked
		{
			uint num = 2166136261u;
			foreach (char c in text)
			{
				num ^= c;
				num *= 16777619;
			}
			return num.ToString("X8");
		}
	}

	private void buttonPreviewPronunciation_Click(object sender, EventArgs e)
	{
		PronunciationEngine.PronunciationResult pronunciationResult = PreparePronunciationResult(richTextBoxContent.Text);
		if (string.IsNullOrWhiteSpace(pronunciationResult.TtsRequestText))
		{
			MessageBox.Show("먼저 변환할 텍스트를 입력해주세요.", "발음 미리보기", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
			return;
		}
		string text = FormatPronunciationPreview(pronunciationResult);
		string text2 = ((text.Length > 7000) ? (text.Substring(0, 7000) + "\r\n\r\n...(미리보기는 7000자까지만 표시됩니다.)") : text);
		MessageBox.Show(text2, "한국어 발음 미리보기", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
	}

	private string FormatPronunciationPreview(PronunciationEngine.PronunciationResult result)
	{
		string text = ((result.RulesApplied.Count == 0) ? "- 적용된 규칙 없음" : string.Join(Environment.NewLine, result.RulesApplied.Select((string rule) => "- " + rule)));
		return "원문\r\n" + result.OriginalText + "\r\n\r\n표준 발음 미리보기\r\n[" + result.StandardPronunciationPreview + "]\r\n\r\nTTS 전송 문장\r\n" + result.TtsRequestText + "\r\n\r\n적용된 규칙\r\n" + text;
	}

	private async Task CreateSibilantDebugSamplesAsync()
	{
		if (!IsSupertonicSelected())
		{
			MessageBox.Show("ㅅ 후보 생성은 Supertonic Local 엔진에서만 사용할 수 있습니다.", "발음 후보 생성", MessageBoxButtons.OK, MessageBoxIcon.Information);
			return;
		}
		var baseResult = PrepareBasePronunciationResult(richTextBoxContent.Text);
		if (string.IsNullOrWhiteSpace(baseResult.TtsRequestText))
		{
			MessageBox.Show("먼저 변환할 텍스트를 입력해주세요.", "발음 후보 생성", MessageBoxButtons.OK, MessageBoxIcon.Information);
			return;
		}
		string voiceId = ((VoiceItem)comboBoxVoice.SelectedItem).VoiceId;
		var debugResult = PronunciationEngine.SupertonicSibilantRescueNormalizer.Normalize(
			baseResult.TtsRequestText,
			voiceId,
			PronunciationEngine.SibilantMode.Debug,
			new PronunciationEngine.SibilantRewriteOptions
			{
				BaseDirectory = InternalRoot,
				Enabled = true
			});
		if (debugResult.Candidates.Count == 0)
		{
			MessageBox.Show("감지된 ㅅ/습니다 계열 위험 문장이 없습니다.", "발음 후보 생성", MessageBoxButtons.OK, MessageBoxIcon.Information);
			return;
		}
		string folder = Path.Combine(InternalRoot, "SupertonicLocal", "cache", "sibilant_debug", voiceId, ShortHash(baseResult.TtsRequestText));
		Directory.CreateDirectory(folder);
		buttonSibilantDebug.Enabled = false;
		labelProgressStatus.Text = "ㅅ 발음 후보 WAV 생성 중...";
		try
		{
			await EnsureSupertonicServerAsync();
			var candidates = debugResult.Candidates.ToList();
			for (int i = 0; i < candidates.Count; i++)
			{
				var candidate = candidates[i];
				labelProgressStatus.Text = $"ㅅ 후보 생성 중... ({i + 1}/{candidates.Count})";
				byte[] wav = await CallSupertonicTtsApi(candidate.TtsText, voiceId, 1.0, Math.Max(GetSelectedSteps(), 10), 0.32);
				string path = Path.Combine(folder, $"{i + 1:00}_{candidate.Id}.wav");
				File.WriteAllBytes(path, wav);
				candidate.FilePath = path;
			}
			var metadata = new JObject
			{
				["originalText"] = baseResult.OriginalText,
				["baseTtsText"] = baseResult.TtsRequestText,
				["voice"] = voiceId,
				["mode"] = "Debug",
				["riskScore"] = debugResult.RiskScore,
				["candidates"] = new JArray(candidates.Select(candidate => new JObject
				{
					["id"] = candidate.Id,
					["label"] = candidate.Label,
					["ttsText"] = candidate.TtsText,
					["file"] = candidate.FilePath == null ? "" : Path.GetFileName(candidate.FilePath)
				}))
			};
			File.WriteAllText(Path.Combine(folder, "metadata.json"), metadata.ToString(), Encoding.UTF8);
			lastGeneratedAudioPath = candidates.FirstOrDefault(c => File.Exists(c.FilePath))?.FilePath;
			buttonPlayGenerated.Enabled = !string.IsNullOrWhiteSpace(lastGeneratedAudioPath);
			buttonStopGenerated.Enabled = buttonPlayGenerated.Enabled;
			Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
			labelProgressStatus.Text = "ㅅ 발음 후보 WAV 생성 완료";
		}
		catch (Exception ex)
		{
			MessageBox.Show("ㅅ 발음 후보 생성 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			UpdateSibilantDebugButton();
		}
	}

	private static string ShortHash(string text)
	{
		unchecked
		{
			uint hash = 2166136261u;
			foreach (char c in text ?? "")
			{
				hash ^= c;
				hash *= 16777619;
			}
			return hash.ToString("X8");
		}
	}

	private async Task EnsureSupertonicServerAsync()
	{
		if (supertonicProcess != null &&
			!supertonicProcess.HasExited &&
			supertonicPort > 0 &&
			await IsSupertonicHealthyAsync(supertonicPort))
		{
			return;
		}
		StopSupertonicServer();
		string text = Path.Combine(InternalRoot, "SupertonicLocal");
		string supertonicPythonPath = GetSupertonicPythonPath(text);
		if (!File.Exists(supertonicPythonPath))
		{
			throw new FileNotFoundException("Supertonic Local Python이 설치되지 않았습니다. _internal\\SupertonicLocal 폴더를 확인해주세요.", supertonicPythonPath);
		}
		ValidateSupertonicModelOrThrow();
		int port = FindAvailableSupertonicPort();
		string secureServer = Path.Combine(text, "app", "secure_server.py");
		if (!File.Exists(secureServer))
		{
			throw new FileNotFoundException("보안 강화 Supertonic 서버 파일이 없습니다.", secureServer);
		}
		Directory.CreateDirectory(Path.Combine(text, "models"));
		Directory.CreateDirectory(Path.Combine(text, "cache"));
		string value = Path.Combine(text, ".venv", "Lib", "site-packages");
		supertonicSessionToken = LocalSidecarSecurity.CreateToken();
		supertonicSessionId = LocalSidecarSecurity.CreateSessionId();
		ProcessStartInfo processStartInfo = new ProcessStartInfo
		{
			FileName = supertonicPythonPath,
			Arguments = $"\"{secureServer}\" --port {port}",
			WorkingDirectory = text,
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true
		};
		processStartInfo.EnvironmentVariables["PYTHONPATH"] = value;
		processStartInfo.EnvironmentVariables["SUPERTONIC_CACHE_DIR"] = Path.Combine(text, "models");
		processStartInfo.EnvironmentVariables["HF_HOME"] = Path.Combine(text, "cache", "huggingface");
		processStartInfo.EnvironmentVariables["HF_HUB_CACHE"] = Path.Combine(text, "cache", "huggingface", "hub");
		processStartInfo.EnvironmentVariables["SUPERTONIC_INTRA_OP_THREADS"] = "12";
		processStartInfo.EnvironmentVariables["SUPERTONIC_INTER_OP_THREADS"] = "2";
		processStartInfo.EnvironmentVariables["PYTHONUTF8"] = "1";
		processStartInfo.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
		processStartInfo.EnvironmentVariables["HF_HUB_OFFLINE"] = "1";
		processStartInfo.EnvironmentVariables["TTS_LOCAL_AUTH_TOKEN"] = supertonicSessionToken;
		processStartInfo.EnvironmentVariables["TTS_LOCAL_SESSION_ID"] = supertonicSessionId;
		processStartInfo.EnvironmentVariables["TTS_LOCAL_MODEL_REVISION"] = SupertonicModelRevision;
		processStartInfo.EnvironmentVariables["PATH"] = Path.GetDirectoryName(supertonicPythonPath) + ";" + Path.Combine(text, ".venv", "Scripts") + ";" + processStartInfo.EnvironmentVariables["PATH"];
		supertonicProcess = new Process
		{
			StartInfo = processStartInfo
		};
		supertonicProcess.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
		{
			AppendSupertonicLog(e.Data);
		};
		supertonicProcess.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
		{
			AppendSupertonicLog(e.Data);
		};
		supertonicProcess.Start();
		supertonicProcess.BeginOutputReadLine();
		supertonicProcess.BeginErrorReadLine();
		supertonicPort = port;
		DateTime deadline = DateTime.Now.AddSeconds(300.0);
		while (DateTime.Now < deadline)
		{
			if (await IsSupertonicHealthyAsync(port))
			{
				return;
			}
			if (supertonicProcess != null && supertonicProcess.HasExited)
			{
				throw new Exception("Supertonic 로컬 서버가 시작 중 종료되었습니다. 모델 파일이 없거나 Hugging Face 접속이 차단되었을 수 있습니다. _internal\\SupertonicLocal\\server.log를 확인해주세요.");
			}
			await Task.Delay(1000);
		}
		throw new Exception("Supertonic 로컬 서버가 300초 안에 준비되지 않았습니다.");
	}

	private string GetSupertonicPythonPath(string localRoot)
	{
		string path = Path.Combine(localRoot, "python");
		if (Directory.Exists(path))
		{
			foreach (string item in from p in Directory.GetDirectories(path, "cpython-*")
				orderby p descending
				select p)
			{
				string text = Path.Combine(item, "python.exe");
				if (File.Exists(text))
				{
					return text;
				}
			}
		}
		return Path.Combine(localRoot, ".venv", "Scripts", "python.exe");
	}

	private void AppendSupertonicLog(string line)
	{
		if (string.IsNullOrWhiteSpace(line))
		{
			return;
		}
		try
		{
			string path = Path.Combine(InternalRoot, "SupertonicLocal", "server.log");
			lock (supertonicLogLock)
			{
				LocalSidecarSecurity.AppendRotatingLog(
					path,
					DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + line + Environment.NewLine);
			}
		}
		catch
		{
		}
	}

	private int FindAvailableSupertonicPort()
	{
		for (int i = 7788; i <= 7798; i++)
		{
			if (IsPortAvailable(i))
			{
				return i;
			}
		}
		throw new Exception("Supertonic 로컬 서버에 사용할 수 있는 포트가 없습니다. 7788~7798 포트를 확인해주세요.");
	}

	private bool IsPortAvailable(int port)
	{
		try
		{
			TcpListener tcpListener = new TcpListener(IPAddress.Loopback, port);
			tcpListener.Start();
			tcpListener.Stop();
			return true;
		}
		catch
		{
			return false;
		}
	}

	private async Task<bool> IsSupertonicHealthyAsync(int port)
	{
		try
		{
			using HttpClient httpClient = LocalSidecarSecurity.CreateLoopbackClient(TimeSpan.FromSeconds(2.0));
			using HttpRequestMessage request = new HttpRequestMessage(
				HttpMethod.Get,
				$"http://127.0.0.1:{port}/v1/health");
			LocalSidecarSecurity.AddToken(request, supertonicSessionToken);
			using HttpResponseMessage response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
			if (!response.IsSuccessStatusCode)
			{
				return false;
			}
			byte[] body = await LocalSidecarSecurity.ReadBoundedAsync(response.Content, 64 * 1024);
			JObject health = JObject.Parse(Encoding.UTF8.GetString(body));
			return string.Equals(health["engine"]?.ToString(), "supertonic", StringComparison.Ordinal)
				&& string.Equals(health["model"]?.ToString(), "supertonic-3", StringComparison.Ordinal)
				&& string.Equals(health["model_revision"]?.ToString(), SupertonicModelRevision, StringComparison.Ordinal)
				&& string.Equals(health["session_id"]?.ToString(), supertonicSessionId, StringComparison.Ordinal)
				&& string.Equals(health["status"]?.ToString(), "ready", StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}

	private async Task<byte[]> CallSupertonicTtsApi(string text, string voiceName, double speed, int steps, double silenceDuration)
	{
		using HttpClient httpClient = LocalSidecarSecurity.CreateLoopbackClient(TimeSpan.FromMinutes(30.0));
		var tuning = PronunciationEngine.SupertonicSibilantRescueNormalizer.BuildPayloadTuning(text, IsSibilantRescueEnabled, SelectedSibilantMode, steps);
		if (tuning.ApplyConservativePayload && GetSelectedSpeed() >= 1.15)
		{
			labelProgressStatus.Text = "빠른 속도에서는 ㅅ/습니다 계열 발음이 뭉개질 수 있어 1.00x 전후를 권장합니다.";
		}
		JObject jObject = JObject.FromObject(new
		{
			text = text,
			voice = voiceName,
			lang = "ko",
			steps = tuning.Steps,
			speed = speed,
			max_chunk_length = tuning.MaxChunkLength,
			silence_duration = tuning.ApplyConservativePayload ? Math.Max(silenceDuration, tuning.SilenceDuration) : silenceDuration,
			response_format = "wav"
		});
		using HttpRequestMessage request = new HttpRequestMessage(
			HttpMethod.Post,
			$"http://127.0.0.1:{supertonicPort}/v1/tts")
		{
			Content = new StringContent(jObject.ToString(), Encoding.UTF8, "application/json")
		};
		LocalSidecarSecurity.AddToken(request, supertonicSessionToken);
		using HttpResponseMessage httpResponseMessage = await httpClient.SendAsync(
			request,
			HttpCompletionOption.ResponseHeadersRead);
		if (httpResponseMessage.IsSuccessStatusCode)
		{
			byte[] wav = await LocalSidecarSecurity.ReadBoundedAsync(
				httpResponseMessage.Content,
				LocalSidecarSecurity.SupertonicResponseLimitBytes);
			ValidateSupertonicOutput(wav);
			return wav;
		}
		byte[] errorBody = await LocalSidecarSecurity.ReadBoundedAsync(httpResponseMessage.Content, 64 * 1024);
		string value = Encoding.UTF8.GetString(errorBody);
		throw new Exception($"Supertonic TTS 오류: {httpResponseMessage.StatusCode}\n{value}");
	}

	private void ValidateSupertonicOutput(byte[] wav)
	{
		WavData data = ReadWavData(wav);
		if (data.AudioFormat != 1 ||
			data.Channels != 1 ||
			data.BitsPerSample != 16 ||
			data.SampleRate < 8000 ||
			data.SampleRate > 192000)
		{
			throw new InvalidDataException(
				$"Supertonic 출력 형식이 올바르지 않습니다: {data.SampleRate}Hz, {data.Channels}채널, {data.BitsPerSample}비트");
		}
	}

	private void buttonOpenModelFolder_Click(object sender, EventArgs e)
	{
		try
		{
			string modelDirectory = IsSupertonicSelected() ? GetSupertonicModelDirectory() : GetVoxModelDirectory();
			Directory.CreateDirectory(modelDirectory);
			Process.Start("explorer.exe", modelDirectory);
		}
		catch (Exception ex)
		{
			MessageBox.Show("모델 폴더를 여는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void buttonOpenLog_Click(object sender, EventArgs e)
	{
		try
		{
			string text = IsSupertonicSelected()
				? Path.Combine(InternalRoot, "SupertonicLocal", "server.log")
				: Path.Combine(GetVoxRoot(), "logs", "server.log");
			Directory.CreateDirectory(Path.GetDirectoryName(text));
			if (!File.Exists(text))
			{
				File.WriteAllText(text, "", Encoding.UTF8);
			}
			Process.Start("notepad.exe", text);
		}
		catch (Exception ex)
		{
			MessageBox.Show("로그를 여는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void StopSupertonicServer()
	{
		try
		{
			if (supertonicProcess != null && !supertonicProcess.HasExited)
			{
				supertonicProcess.Kill(entireProcessTree: true);
				supertonicProcess.Dispose();
			}
		}
		catch
		{
		}
		supertonicProcess = null;
		supertonicPort = 0;
		supertonicSessionToken = "";
		supertonicSessionId = "";
	}

	private async Task EnsureVoxServerAsync()
	{
		if (voxProcess != null && !voxProcess.HasExited && voxPort > 0 && await IsVoxHealthyAsync(voxPort))
		{
			return;
		}
		if (!StopVoxServer())
		{
			throw new Exception("기존 VoxCPM2 서버 프로세스 트리의 종료를 확인하지 못해 새 서버 시작을 차단했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.");
		}
		StopSupertonicServer();
		ValidateVoxInstallationOrThrow();
		EnsureVoxMemoryAvailable();
		bool createdNew;
		voxModelMutex = new Mutex(true, @"Local\SupertonicPlusVoxCPM2_ModelHost", out createdNew);
		if (!createdNew)
		{
			voxModelMutex.Dispose();
			voxModelMutex = null;
			throw new Exception("다른 프로그램 인스턴스가 이미 VoxCPM2 모델을 사용 중입니다. 해당 창에서 작업을 마친 뒤 다시 시도해주세요.");
		}
		string root = GetVoxRoot();
		string python = Path.Combine(root, "python", "python.exe");
		string server = Path.Combine(root, "app", "server.py");
		int port = FindAvailableVoxPort();
		voxSessionToken = LocalSidecarSecurity.CreateToken();
		voxSessionId = LocalSidecarSecurity.CreateSessionId();
		Directory.CreateDirectory(Path.Combine(root, "logs"));
		Directory.CreateDirectory(Path.Combine(root, "cache", "samples"));
		Directory.CreateDirectory(Path.Combine(root, "voices", "user"));
		ProcessStartInfo startInfo = new ProcessStartInfo
		{
			FileName = python,
			Arguments = $"\"{server}\" --port {port} --preload",
			WorkingDirectory = root,
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true
		};
		startInfo.EnvironmentVariables["PYTHONPATH"] = Path.Combine(root, "pkgs");
		startInfo.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
		startInfo.EnvironmentVariables["PYTHONUTF8"] = "1";
		startInfo.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
		startInfo.EnvironmentVariables["HF_HUB_OFFLINE"] = "1";
		startInfo.EnvironmentVariables["TRANSFORMERS_OFFLINE"] = "1";
		startInfo.EnvironmentVariables["HF_DATASETS_OFFLINE"] = "1";
			startInfo.EnvironmentVariables["OMP_NUM_THREADS"] = "12";
			startInfo.EnvironmentVariables["MKL_NUM_THREADS"] = "12";
			startInfo.EnvironmentVariables["VOXCPM_INTRA_OP_THREADS"] = "12";
			startInfo.EnvironmentVariables["VOXCPM_INTER_OP_THREADS"] = "2";
		startInfo.EnvironmentVariables["VOXCPM_MODEL_DIR"] = GetVoxModelDirectory();
		startInfo.EnvironmentVariables["VOXCPM_MODEL_REVISION"] = VoxModelRevision;
		startInfo.EnvironmentVariables["VOXCPM_OFFLINE"] = "1";
		startInfo.EnvironmentVariables["TTS_LOCAL_AUTH_TOKEN"] = voxSessionToken;
		startInfo.EnvironmentVariables["TTS_LOCAL_SESSION_ID"] = voxSessionId;
		startInfo.EnvironmentVariables["PATH"] = Path.GetDirectoryName(python) + ";" + startInfo.EnvironmentVariables["PATH"];
		voxProcess = new Process { StartInfo = startInfo };
		voxProcess.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { AppendVoxLog(e.Data); };
		voxProcess.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { AppendVoxLog(e.Data); };
		try
		{
			voxProcess.Start();
			voxProcess.BeginOutputReadLine();
			voxProcess.BeginErrorReadLine();
			voxPort = port;
			DateTime deadline = DateTime.Now.AddMinutes(10.0);
			while (DateTime.Now < deadline)
			{
				generationCancellation?.Token.ThrowIfCancellationRequested();
				if (await IsVoxHealthyAsync(port))
				{
					return;
				}
				if (voxProcess.HasExited)
				{
					int exitCode = -1;
					try { exitCode = voxProcess.ExitCode; } catch { }
					if (exitCode == -1073741819)
					{
						throw new Exception("VoxCPM2가 메모리 부족으로 CPU 모델을 불러오지 못했습니다. Premiere·Chrome 등 메모리를 많이 쓰는 프로그램을 닫고, 가용 메모리 12GB 이상을 확보한 뒤 다시 시도해주세요.");
					}
					throw new Exception($"VoxCPM2 서버가 모델을 준비하는 중 종료되었습니다(종료 코드 {exitCode}). _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.");
				}
				await Task.Delay(1000);
			}
			throw new TimeoutException("VoxCPM2 모델이 10분 안에 준비되지 않았습니다.");
		}
		catch (Exception startupError)
		{
			if (!StopVoxServer())
			{
				throw new InvalidOperationException("VoxCPM2 서버 준비 실패 후 프로세스 트리의 종료를 확인하지 못했습니다. 소유권과 뮤텍스는 유지했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.", startupError);
			}
			throw;
		}
	}

	private int FindAvailableVoxPort()
	{
		for (int port = 7800; port <= 7810; port++)
		{
			if (IsPortAvailable(port))
			{
				return port;
			}
		}
		throw new Exception("VoxCPM2 서버에 사용할 수 있는 포트가 없습니다. 7800~7810 포트를 확인해주세요.");
	}

	private async Task<bool> IsVoxHealthyAsync(int port)
	{
		try
		{
			using HttpClientHandler handler = new HttpClientHandler { UseProxy = false };
			using HttpClient client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
			using HttpRequestMessage request = new HttpRequestMessage(
				HttpMethod.Get,
				$"http://127.0.0.1:{port}/v1/health");
			LocalSidecarSecurity.AddToken(request, voxSessionToken);
			using HttpResponseMessage response = await client.SendAsync(
				request,
				HttpCompletionOption.ResponseHeadersRead);
			if (!response.IsSuccessStatusCode)
			{
				return false;
			}
			byte[] healthBody = await LocalSidecarSecurity.ReadBoundedAsync(response.Content, 64 * 1024);
			JObject health = JObject.Parse(Encoding.UTF8.GetString(healthBody));
			return string.Equals(health["engine"]?.ToString(), "voxcpm2", StringComparison.OrdinalIgnoreCase)
				&& string.Equals(health["model_revision"]?.ToString(), VoxModelRevision, StringComparison.Ordinal)
				&& string.Equals(health["session_id"]?.ToString(), voxSessionId, StringComparison.Ordinal)
				&& string.Equals(health["status"]?.ToString(), "ready", StringComparison.OrdinalIgnoreCase)
				&& (health["model_loaded"]?.Value<bool>() ?? false);
		}
		catch
		{
			return false;
		}
	}

	private async Task<byte[]> CallVoxTtsApi(string text, string profileId, string? referencePath, int inferenceSteps, int seed, CancellationToken cancellationToken)
	{
		bool clone = string.Equals(profileId, "vox_clone", StringComparison.Ordinal);
		JObject payload = JObject.FromObject(new
		{
			text,
			mode = clone ? "clone" : "preset",
			profile_id = profileId,
			reference_wav_path = clone ? referencePath : null,
			cfg_value = 2.0,
			inference_timesteps = inferenceSteps,
			seed,
			response_format = "wav"
		});
		try
		{
			using HttpClientHandler handler = new HttpClientHandler { UseProxy = false };
			using HttpClient client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(30) };
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{voxPort}/v1/tts")
			{
				Content = new StringContent(payload.ToString(), Encoding.UTF8, "application/json")
			};
			LocalSidecarSecurity.AddToken(request, voxSessionToken);
			using HttpResponseMessage response = await client.SendAsync(
				request,
				HttpCompletionOption.ResponseHeadersRead,
				cancellationToken);
			if (!response.IsSuccessStatusCode)
			{
				byte[] errorBody = await LocalSidecarSecurity.ReadBoundedAsync(
					response.Content,
					64 * 1024,
					cancellationToken);
				string detail = Encoding.UTF8.GetString(errorBody);
				throw new Exception($"VoxCPM2 TTS 오류: {response.StatusCode}\n{detail}");
			}
			return await LocalSidecarSecurity.ReadBoundedAsync(
				response.Content,
				LocalSidecarSecurity.VoxResponseLimitBytes,
				cancellationToken);
		}
		catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
		{
			if (!StopVoxServer())
			{
				throw new InvalidOperationException("VoxCPM2 요청이 30분 제한 시간을 초과했지만 서버 프로세스 트리의 종료를 확인하지 못했습니다. 서버 소유권과 뮤텍스는 유지했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.", ex);
			}
			throw new TimeoutException("VoxCPM2 요청이 30분 제한 시간을 초과해 앱이 시작한 서버를 종료했습니다.", ex);
		}
	}

	private void ValidateVoxOutput(byte[] wav)
	{
		WavData data = ReadWavData(wav);
		if (data.AudioFormat != 1 || data.SampleRate != 48000 || data.Channels != 1 || data.BitsPerSample != 16)
		{
			throw new Exception($"VoxCPM2 출력 형식이 올바르지 않습니다: {data.SampleRate}Hz, {data.Channels}채널, {data.BitsPerSample}비트");
		}
	}

	private void AppendVoxLog(string line)
	{
		if (string.IsNullOrWhiteSpace(line))
		{
			return;
		}
		try
		{
			string log = Path.Combine(GetVoxRoot(), "logs", "server.log");
			Directory.CreateDirectory(Path.GetDirectoryName(log));
			lock (voxLogLock)
			{
				LocalSidecarSecurity.AppendRotatingLog(
					log,
					DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + line + Environment.NewLine);
			}
		}
		catch { }
	}

	private bool StopVoxServer()
	{
		Process? ownedProcess = voxProcess;
		int ownedPort = voxPort;
		if (ownedProcess == null)
		{
			voxPort = 0;
			voxSessionToken = "";
			voxSessionId = "";
			ReleaseVoxModelMutexAfterVerifiedStop();
			return true;
		}

		int processId;
		try
		{
			processId = ownedProcess.Id;
		}
		catch (InvalidOperationException)
		{
			LogVoxLifecycle("Vox process object had no started operating-system process; releasing local ownership.");
			ownedProcess.Dispose();
			voxProcess = null;
			voxPort = 0;
			voxSessionToken = "";
			voxSessionId = "";
			ReleaseVoxModelMutexAfterVerifiedStop();
			return true;
		}
		catch (Exception ex)
		{
			LogVoxLifecycle($"CRITICAL: unable to identify owned Vox process; ownership retained. {ex.GetType().Name}: {ex.Message}");
			return false;
		}

		bool verifiedStopped = false;
		for (int attempt = 1; attempt <= 3 && !verifiedStopped; attempt++)
		{
			bool rootExited = false;
			try
			{
				ownedProcess.Refresh();
				rootExited = ownedProcess.HasExited;
			}
			catch (Exception ex)
			{
				LogVoxLifecycle($"Stop attempt {attempt}/3 could not read PID {processId} state: {ex.GetType().Name}: {ex.Message}");
			}

			if (!rootExited)
			{
				try
				{
					LogVoxLifecycle($"Stop attempt {attempt}/3: killing owned Vox process tree PID {processId}.");
					ownedProcess.Kill(entireProcessTree: true);
				}
				catch (Exception ex)
				{
					LogVoxLifecycle($"Stop attempt {attempt}/3 kill failed for PID {processId}: {ex.GetType().Name}: {ex.Message}");
				}

				try
				{
					rootExited = ownedProcess.WaitForExit(4000);
				}
				catch (Exception ex)
				{
					LogVoxLifecycle($"Stop attempt {attempt}/3 wait failed for PID {processId}: {ex.GetType().Name}: {ex.Message}");
				}
			}

			bool portReleased = rootExited && WaitForVoxPortRelease(ownedPort, 1500);
			verifiedStopped = rootExited && portReleased;
			if (!verifiedStopped)
			{
				LogVoxLifecycle($"Stop attempt {attempt}/3 not yet verified for PID {processId}: rootExited={rootExited}, portReleased={portReleased}.");
				if (attempt < 3)
				{
					Thread.Sleep(250);
				}
			}
		}

		if (!verifiedStopped)
		{
			LogVoxLifecycle($"CRITICAL: owned Vox process tree PID {processId} did not stop after 3 bounded attempts. Process reference, port {ownedPort}, and model mutex are retained to prevent a silent orphan or duplicate model host.");
			return false;
		}

		LogVoxLifecycle($"Verified owned Vox process tree PID {processId} stopped and loopback port {ownedPort} was released.");
		try { ownedProcess.Dispose(); }
		catch (Exception ex) { LogVoxLifecycle($"Vox process dispose warning for PID {processId}: {ex.GetType().Name}: {ex.Message}"); }
		if (ReferenceEquals(voxProcess, ownedProcess))
		{
			voxProcess = null;
			voxPort = 0;
			voxSessionToken = "";
			voxSessionId = "";
		}
		ReleaseVoxModelMutexAfterVerifiedStop();
		return true;
	}

	private bool WaitForVoxPortRelease(int port, int timeoutMilliseconds)
	{
		if (port <= 0)
		{
			return true;
		}
		Stopwatch stopwatch = Stopwatch.StartNew();
		do
		{
			if (IsPortAvailable(port))
			{
				return true;
			}
			Thread.Sleep(100);
		}
		while (stopwatch.ElapsedMilliseconds < timeoutMilliseconds);
		return IsPortAvailable(port);
	}

	private void ReleaseVoxModelMutexAfterVerifiedStop()
	{
		if (voxModelMutex == null)
		{
			return;
		}
		try
		{
			voxModelMutex.ReleaseMutex();
		}
		catch (ApplicationException ex)
		{
			LogVoxLifecycle("Vox model mutex release warning: " + ex.Message);
		}
		finally
		{
			voxModelMutex.Dispose();
			voxModelMutex = null;
		}
	}

	private void LogVoxLifecycle(string message)
	{
		Trace.WriteLine("[VoxCPM2 lifecycle] " + message);
		AppendVoxLog("[lifecycle] " + message);
	}

	private void EnsureVoxMemoryAvailable()
	{
		ulong available = GetAvailablePhysicalMemoryBytes();
		MemoryStatusEx memoryStatus = new MemoryStatusEx();
		ulong commitHeadroom = GlobalMemoryStatusEx(memoryStatus) ? memoryStatus.ullAvailPageFile : 0;
		const ulong twelveGiB = 12UL * 1024 * 1024 * 1024;
		if (commitHeadroom > 0 && commitHeadroom < twelveGiB)
		{
			throw new Exception($"VoxCPM2를 시작할 커밋 메모리가 부족합니다. 현재 여유는 {commitHeadroom / 1024.0 / 1024.0 / 1024.0:0.0}GB이며 안정적인 실행에는 12GB 이상이 필요합니다. Premiere·Chrome 등 메모리를 많이 쓰는 프로그램을 닫거나 Windows 페이지 파일을 늘려주세요.");
		}
		if (available > 0 && available < twelveGiB)
		{
			throw new Exception($"가용 메모리가 {available / 1024.0 / 1024.0 / 1024.0:0.0}GB뿐이라 VoxCPM2를 시작할 수 없습니다. 안정적인 실행에는 12GB 이상을 확보해주세요. Premiere·Chrome 등 메모리를 많이 쓰는 프로그램을 닫아주세요.");
		}
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
	private sealed class MemoryStatusEx
	{
		public uint dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>();
		public uint dwMemoryLoad;
		public ulong ullTotalPhys;
		public ulong ullAvailPhys;
		public ulong ullTotalPageFile;
		public ulong ullAvailPageFile;
		public ulong ullTotalVirtual;
		public ulong ullAvailVirtual;
		public ulong ullAvailExtendedVirtual;
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatusEx buffer);

	private static ulong GetAvailablePhysicalMemoryBytes()
	{
		MemoryStatusEx status = new MemoryStatusEx();
		return GlobalMemoryStatusEx(status) ? status.ullAvailPhys : 0;
	}

	private void SetLastGeneratedAudio(string path, bool autoPlay)
	{
		lastGeneratedAudioPath = path;
		buttonPlayGenerated.Enabled = File.Exists(path);
		buttonStopGenerated.Enabled = buttonPlayGenerated.Enabled;
		if (autoPlay)
		{
			PlayGeneratedAudio();
		}
	}

	private void PlayGeneratedAudio()
	{
		if (string.IsNullOrWhiteSpace(lastGeneratedAudioPath) || !File.Exists(lastGeneratedAudioPath))
		{
			MessageBox.Show("재생할 생성 음성 파일이 없습니다.", "파일 없음", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			buttonPlayGenerated.Enabled = false;
			buttonStopGenerated.Enabled = false;
		}
		else
		{
			soundPlayer.Stop();
			soundPlayer.SoundLocation = lastGeneratedAudioPath;
			soundPlayer.Play();
		}
	}

	private void buttonPlayGenerated_Click(object sender, EventArgs e)
	{
		PlayGeneratedAudio();
	}

	private void buttonStopGenerated_Click(object sender, EventArgs e)
	{
		if (generationInProgress)
		{
			generationCancellation?.Cancel();
			if (!IsSupertonicSelected())
			{
				if (!StopVoxServer())
				{
					labelProgressStatus.Text = "VoxCPM2 종료 확인 실패";
					MessageBox.Show("VoxCPM2 서버 프로세스 트리의 종료를 확인하지 못했습니다. 소유권과 뮤텍스는 유지했습니다. _internal\\VoxCPM2Local\\logs\\server.log를 확인해주세요.", "VoxCPM2 종료 확인 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
					return;
				}
			}
			labelProgressStatus.Text = "생성 취소 중...";
			return;
		}
		soundPlayer.Stop();
	}

	private byte[] MergeWavFiles(List<byte[]> wavFiles)
	{
		if (wavFiles.Count == 0)
		{
			return Array.Empty<byte>();
		}
		if (wavFiles.Count == 1)
		{
			return wavFiles[0];
		}
		List<WavData> list = wavFiles.Select(ReadWavData).ToList();
		WavData wavData = list[0];
		List<byte> list2 = new List<byte>();
		foreach (WavData item in list)
		{
			if (item.SampleRate != wavData.SampleRate || item.Channels != wavData.Channels || item.BitsPerSample != wavData.BitsPerSample)
			{
				throw new Exception("WAV 형식이 서로 달라 병합할 수 없습니다.");
			}
			list2.AddRange(item.Data);
		}
		return BuildWav(list2.ToArray(), wavData.SampleRate, wavData.Channels, wavData.BitsPerSample);
	}

	private WavData ReadWavData(byte[] wav)
	{
		if (wav.Length < 44 || Encoding.ASCII.GetString(wav, 0, 4) != "RIFF" || Encoding.ASCII.GetString(wav, 8, 4) != "WAVE")
		{
			throw new Exception("올바른 WAV 파일이 아닙니다.");
		}
		int audioFormat = 0;
		int num = 0;
		int num2 = 0;
		int num3 = 0;
		byte[] array = null;
		int num4 = 12;
		while (num4 + 8 <= wav.Length)
		{
			string text = Encoding.ASCII.GetString(wav, num4, 4);
			uint unsignedChunkSize = BitConverter.ToUInt32(wav, num4 + 4);
			if (unsignedChunkSize > int.MaxValue)
			{
				throw new Exception("WAV 청크 크기가 허용 범위를 초과했습니다.");
			}
			int num5 = (int)unsignedChunkSize;
			int num6 = checked(num4 + 8);
			long chunkEnd = (long)num6 + num5;
			if (chunkEnd > wav.LongLength)
			{
				throw new Exception("WAV 청크 크기가 손상되었습니다.");
			}
			if (text == "fmt ")
			{
				if (num5 < 16)
				{
					throw new Exception("WAV 형식 청크가 손상되었습니다.");
				}
				audioFormat = BitConverter.ToUInt16(wav, num6);
				num2 = BitConverter.ToUInt16(wav, num6 + 2);
				num = BitConverter.ToInt32(wav, num6 + 4);
				num3 = BitConverter.ToUInt16(wav, num6 + 14);
			}
			else if (text == "data")
			{
				array = new byte[num5];
				Buffer.BlockCopy(wav, num6, array, 0, num5);
			}
			long nextChunk = chunkEnd + (num5 & 1);
			if (nextChunk > int.MaxValue)
			{
				throw new Exception("WAV 청크 오프셋이 허용 범위를 초과했습니다.");
			}
			num4 = (int)nextChunk;
		}
		if (array == null || array.Length == 0 || audioFormat == 0 || num == 0 || num2 == 0 || num3 == 0)
		{
			throw new Exception("WAV 데이터를 읽을 수 없습니다.");
		}
		return new WavData
		{
			AudioFormat = audioFormat,
			SampleRate = num,
			Channels = num2,
			BitsPerSample = num3,
			Data = array
		};
	}

	private byte[] BuildWav(byte[] pcmData, int sampleRate, int channels, int bitsPerSample)
	{
		byte[] array = new byte[44];
		Encoding.ASCII.GetBytes("RIFF").CopyTo(array, 0);
		BitConverter.GetBytes(pcmData.Length + 36).CopyTo(array, 4);
		Encoding.ASCII.GetBytes("WAVE").CopyTo(array, 8);
		Encoding.ASCII.GetBytes("fmt ").CopyTo(array, 12);
		BitConverter.GetBytes(16).CopyTo(array, 16);
		BitConverter.GetBytes((ushort)1).CopyTo(array, 20);
		BitConverter.GetBytes((ushort)channels).CopyTo(array, 22);
		BitConverter.GetBytes(sampleRate).CopyTo(array, 24);
		BitConverter.GetBytes(sampleRate * channels * bitsPerSample / 8).CopyTo(array, 28);
		BitConverter.GetBytes((ushort)(channels * bitsPerSample / 8)).CopyTo(array, 32);
		BitConverter.GetBytes((ushort)bitsPerSample).CopyTo(array, 34);
		Encoding.ASCII.GetBytes("data").CopyTo(array, 36);
		BitConverter.GetBytes(pcmData.Length).CopyTo(array, 40);
		byte[] array2 = new byte[array.Length + pcmData.Length];
		array.CopyTo(array2, 0);
		pcmData.CopyTo(array2, array.Length);
		return array2;
	}

	private byte[] ApplyVoicePostProcessingToWav(byte[] wav, double speedFactor, int pitchSemitones, double volumeFactor)
	{
		byte[] array = wav;
		if (Math.Abs(speedFactor - 1.0) >= 0.01)
		{
			array = ApplySpeedToWav(array, speedFactor);
		}
		if (Math.Abs(volumeFactor - 1.0) >= 0.01)
		{
			array = ApplyGainToWav(array, volumeFactor);
		}
		return array;
	}

	private byte[] ApplyGainToWav(byte[] wav, double gain)
	{
		if (wav == null || wav.Length < 44 || Math.Abs(gain - 1.0) < 0.01)
		{
			return wav;
		}
		WavData wavData = ReadWavData(wav);
		if (wavData.BitsPerSample != 16)
		{
			return wav;
		}
		byte[] array = new byte[wavData.Data.Length];
		for (int i = 0; i + 1 < wavData.Data.Length; i += 2)
		{
			short num = BitConverter.ToInt16(wavData.Data, i);
			BitConverter.GetBytes(ClampToShort((double)num * gain)).CopyTo(array, i);
		}
		return BuildWav(array, wavData.SampleRate, wavData.Channels, wavData.BitsPerSample);
	}

	private byte[] ApplyPitchToWav(byte[] wav, int semitones)
	{
		if (wav == null || wav.Length < 44 || semitones == 0)
		{
			return wav;
		}
		WavData wavData = ReadWavData(wav);
		if (wavData.BitsPerSample != 16)
		{
			return wav;
		}
		double pitchFactor = Math.Pow(2.0, (double)semitones / 12.0);
		byte[] pcmData = ApplyPitchToPcmByChannel(wavData.Data, pitchFactor, wavData.Channels);
		return BuildWav(pcmData, wavData.SampleRate, wavData.Channels, wavData.BitsPerSample);
	}

	private byte[] ApplyPitchToPcmByChannel(byte[] pcmData, double pitchFactor, int channels)
	{
		if (channels <= 1)
		{
			return ApplyPitchToPcm(pcmData, pitchFactor);
		}
		int num = pcmData.Length / 2 / channels;
		if (num < 2048)
		{
			return pcmData;
		}
		short[][] array = new short[channels][];
		for (int i = 0; i < channels; i++)
		{
			array[i] = new short[num];
		}
		for (int j = 0; j < num; j++)
		{
			for (int k = 0; k < channels; k++)
			{
				array[k][j] = BitConverter.ToInt16(pcmData, (j * channels + k) * 2);
			}
		}
		short[][] array2 = new short[channels][];
		for (int l = 0; l < channels; l++)
		{
			array2[l] = PitchShiftPcm(array[l], pitchFactor);
		}
		byte[] array3 = new byte[num * channels * 2];
		for (int m = 0; m < num; m++)
		{
			for (int n = 0; n < channels; n++)
			{
				BitConverter.GetBytes(array2[n][m]).CopyTo(array3, (m * channels + n) * 2);
			}
		}
		return array3;
	}

	private byte[] ApplyPitchToPcm(byte[] pcmData, double pitchFactor)
	{
		if (pcmData == null || pcmData.Length < 4096 || Math.Abs(pitchFactor - 1.0) < 0.001)
		{
			return pcmData;
		}
		int num = pcmData.Length / 2;
		short[] array = new short[num];
		Buffer.BlockCopy(pcmData, 0, array, 0, num * 2);
		short[] array2 = PitchShiftPcm(array, pitchFactor);
		byte[] array3 = new byte[array2.Length * 2];
		Buffer.BlockCopy(array2, 0, array3, 0, array3.Length);
		return array3;
	}

	private short[] PitchShiftPcm(short[] samples, double pitchFactor)
	{
		if (samples == null || samples.Length < 2048 || Math.Abs(pitchFactor - 1.0) < 0.001)
		{
			return samples;
		}
		int newLength = Math.Max(1024, (int)Math.Round((double)samples.Length / pitchFactor));
		short[] samples2 = ResamplePcm(samples, newLength);
		short[] samples3 = TimeScalePcm(samples2, 1.0 / pitchFactor);
		return MatchPcmLength(samples3, samples.Length);
	}

	private short[] ResamplePcm(short[] samples, int newLength)
	{
		if (samples == null || samples.Length == 0 || newLength <= 0)
		{
			return Array.Empty<short>();
		}
		if (newLength == samples.Length)
		{
			short[] array = new short[samples.Length];
			Array.Copy(samples, array, samples.Length);
			return array;
		}
		short[] array2 = new short[newLength];
		double num = (double)(samples.Length - 1) / (double)Math.Max(1, newLength - 1);
		for (int i = 0; i < newLength; i++)
		{
			double num2 = (double)i * num;
			int num3 = (int)Math.Floor(num2);
			int num4 = Math.Min(samples.Length - 1, num3 + 1);
			double num5 = num2 - (double)num3;
			array2[i] = ClampToShort((double)samples[num3] * (1.0 - num5) + (double)samples[num4] * num5);
		}
		return array2;
	}

	private short[] MatchPcmLength(short[] samples, int targetLength)
	{
		if (samples == null)
		{
			return new short[targetLength];
		}
		if (samples.Length == targetLength)
		{
			return samples;
		}
		if (Math.Abs(samples.Length - targetLength) > targetLength / 20)
		{
			return ResamplePcm(samples, targetLength);
		}
		short[] array = new short[targetLength];
		Array.Copy(samples, array, Math.Min(samples.Length, targetLength));
		return array;
	}

	private byte[] ApplySpeedToWav(byte[] wav, double speedFactor)
	{
		if (wav == null || wav.Length < 44 || Math.Abs(speedFactor - 1.0) < 0.01)
		{
			return wav;
		}
		WavData wavData = ReadWavData(wav);
		if (wavData.BitsPerSample != 16)
		{
			return wav;
		}
		byte[] pcmData = ApplySpeedToPcmByChannel(wavData.Data, speedFactor, wavData.Channels);
		return BuildWav(pcmData, wavData.SampleRate, wavData.Channels, wavData.BitsPerSample);
	}

	private byte[] ApplySpeedToPcmByChannel(byte[] pcmData, double speedFactor, int channels)
	{
		if (channels <= 1)
		{
			return ApplySpeedToPcm(pcmData, speedFactor);
		}
		int num = pcmData.Length / 2 / channels;
		if (num < 2048)
		{
			return pcmData;
		}
		short[][] array = new short[channels][];
		for (int i = 0; i < channels; i++)
		{
			array[i] = new short[num];
		}
		for (int j = 0; j < num; j++)
		{
			for (int k = 0; k < channels; k++)
			{
				array[k][j] = BitConverter.ToInt16(pcmData, (j * channels + k) * 2);
			}
		}
		short[][] array2 = new short[channels][];
		int num2 = int.MaxValue;
		for (int l = 0; l < channels; l++)
		{
			array2[l] = TimeScalePcm(array[l], speedFactor);
			num2 = Math.Min(num2, array2[l].Length);
		}
		byte[] array3 = new byte[num2 * channels * 2];
		for (int m = 0; m < num2; m++)
		{
			for (int n = 0; n < channels; n++)
			{
				BitConverter.GetBytes(array2[n][m]).CopyTo(array3, (m * channels + n) * 2);
			}
		}
		return array3;
	}

	private string GetSampleDirectory()
	{
		return IsSupertonicSelected()
			? Path.Combine(InternalRoot, "SupertonicLocal", "cache", IsSibilantRescueEnabled ? "samples_sibilant" : "samples")
			: Path.Combine(GetVoxRoot(), "cache", "samples");
	}

	private string GetBundledSamplePath(bool voxSample, string voiceId)
	{
		string engineDirectory = voxSample ? "VoxCPM2" : "Supertonic";
		return Path.Combine(InternalRoot, "VoiceSamples", engineDirectory, voiceId + ".wav");
	}

	private static bool IsUsableBundledSample(string path)
	{
		try
		{
			FileInfo fileInfo = new FileInfo(path);
			if (!fileInfo.Exists || fileInfo.Length < 44)
			{
				return false;
			}
			byte[] array = new byte[12];
			using FileStream fileStream = File.OpenRead(path);
			if (fileStream.Read(array, 0, array.Length) != array.Length)
			{
				return false;
			}
			return Encoding.ASCII.GetString(array, 0, 4) == "RIFF" && Encoding.ASCII.GetString(array, 8, 4) == "WAVE";
		}
		catch
		{
			return false;
		}
	}

	private string GetSamplePath(string engineName, string voiceId, int speedValue, int steps)
	{
		return GetSamplePath(engineName, voiceId, speedValue, steps, trackBarPitch?.Value ?? 0, trackBarVolume?.Value ?? 100, trackBarPause?.Value ?? 25);
	}

	private string GetSamplePath(string engineName, string voiceId, int speedValue, int steps, int pitchValue, int volumeValue, int pauseValue)
	{
		string referenceToken = voiceId == "vox_clone" ? ShortHash(voxReferenceId ?? "") : "preset";
		return Path.Combine(GetSampleDirectory(), $"{engineName}_{voiceId}_{referenceToken}_{speedValue}_{steps}_p{pitchValue}_v{volumeValue}_s{pauseValue}_pr{PronunciationCacheToken()}_{SampleCacheVersion}.wav");
	}

	private string GetBaseSamplePath(string engineName, string voiceId, int steps, int pauseValue)
	{
		return Path.Combine(GetSampleDirectory(), $"{engineName}_{voiceId}_base_{steps}_s{pauseValue}_pr{PronunciationCacheToken()}_{SampleCacheVersion}.wav");
	}

	private void WriteSampleFile(string path, byte[] bytes)
	{
		Directory.CreateDirectory(Path.GetDirectoryName(path));
		string text = path + ".tmp";
		File.WriteAllBytes(text, bytes);
		if (File.Exists(path))
		{
			File.Delete(path);
		}
		File.Move(text, path);
	}

	private async Task<byte[]> CreateSupertonicSampleBaseAsync(string voiceId, int steps, int pauseValue)
	{
		byte[] first = await CallSupertonicTtsApi(PrepareTextForSupertonic("샘플 음성입니다."), voiceId, 1.0, steps, 0.0);
		byte[] second = await CallSupertonicTtsApi(PrepareTextForSupertonic("안녕하세요"), voiceId, 1.0, steps, 0.0);
		return MergeWavFilesWithSilence(new List<byte[]> { first, second }, (double)pauseValue / 100.0);
	}

	private byte[] MergeWavFilesWithSilence(List<byte[]> wavFiles, double silenceSeconds)
	{
		if (wavFiles.Count == 0)
		{
			return Array.Empty<byte>();
		}
		if (wavFiles.Count == 1)
		{
			return wavFiles[0];
		}
		List<WavData> list = wavFiles.Select(ReadWavData).ToList();
		WavData wavData = list[0];
		List<byte> list2 = new List<byte>();
		int silenceByteCount = Math.Max(0, (int)Math.Round((double)wavData.SampleRate * silenceSeconds) * wavData.Channels * wavData.BitsPerSample / 8);
		if (wavData.BitsPerSample == 16 && silenceByteCount % 2 != 0)
		{
			silenceByteCount++;
		}
		int fadeSamples = Math.Max(1, (int)Math.Round((double)wavData.SampleRate * 0.005));
		for (int i = 0; i < list.Count; i++)
		{
			WavData item = list[i];
			if (item.SampleRate != wavData.SampleRate || item.Channels != wavData.Channels || item.BitsPerSample != wavData.BitsPerSample)
			{
				throw new Exception("WAV 형식이 서로 달라 병합할 수 없습니다.");
			}
			byte[] audioData = item.Data;
			if (i > 0)
			{
				if (silenceByteCount > 0)
				{
					list2.AddRange(new byte[silenceByteCount]);
				}
				if (wavData.BitsPerSample == 16 && audioData.Length >= fadeSamples * 2)
				{
					audioData = ApplyFadeInToAudio(audioData, fadeSamples);
				}
			}
			if (i < list.Count - 1 && wavData.BitsPerSample == 16 && audioData.Length >= fadeSamples * 2)
			{
				audioData = ApplyFadeOutToAudio(audioData, fadeSamples);
			}
			list2.AddRange(audioData);
		}
		return BuildWav(list2.ToArray(), wavData.SampleRate, wavData.Channels, wavData.BitsPerSample);
	}

	private byte[] ApplyFadeInToAudio(byte[] audioData, int fadeSamples)
	{
		byte[] result = new byte[audioData.Length];
		Array.Copy(audioData, result, audioData.Length);
		for (int i = 0; i < fadeSamples && i * 2 + 1 < result.Length; i++)
		{
			double fadeAmount = (double)i / (double)fadeSamples;
			short sample = BitConverter.ToInt16(result, i * 2);
			short faded = (short)Math.Round((double)sample * fadeAmount);
			BitConverter.GetBytes(faded).CopyTo(result, i * 2);
		}
		return result;
	}

	private byte[] ApplyFadeOutToAudio(byte[] audioData, int fadeSamples)
	{
		byte[] result = new byte[audioData.Length];
		Array.Copy(audioData, result, audioData.Length);
		int startSample = Math.Max(0, result.Length / 2 - fadeSamples);
		for (int i = 0; i < fadeSamples && startSample * 2 + i * 2 + 1 < result.Length; i++)
		{
			double fadeAmount = 1.0 - ((double)i / (double)fadeSamples);
			short sample = BitConverter.ToInt16(result, (startSample + i) * 2);
			short faded = (short)Math.Round((double)sample * fadeAmount);
			BitConverter.GetBytes(faded).CopyTo(result, (startSample + i) * 2);
		}
		return result;
	}

	private void QueueSupertonicSampleWarmup()
	{
		if (supertonicSampleVoices.All((string voice) => IsUsableBundledSample(GetBundledSamplePath(false, voice))))
		{
			return;
		}
		if (IsSupertonicSelected() && trackBarSpeed != null && comboBoxQuality != null && labelProgressStatus != null && HasSupertonicModelFiles())
		{
			requestedSampleWarmupSpeed = trackBarSpeed.Value;
			requestedSampleWarmupSteps = GetSelectedSteps();
			requestedSampleWarmupPitch = trackBarPitch?.Value ?? 0;
			requestedSampleWarmupVolume = trackBarVolume?.Value ?? 100;
			requestedSampleWarmupPause = trackBarPause?.Value ?? 25;
			if (!sampleWarmupRunning)
			{
				_ = WarmupSupertonicSamplesLoopAsync();
			}
		}
	}

	private async Task WarmupSupertonicSamplesLoopAsync()
	{
		sampleWarmupRunning = true;
		try
		{
			while (IsSupertonicSelected())
			{
				int speedValue = requestedSampleWarmupSpeed;
				int steps = requestedSampleWarmupSteps;
				int pitchValue = requestedSampleWarmupPitch;
				int volumeValue = requestedSampleWarmupVolume;
				int pauseValue = requestedSampleWarmupPause;
				await WarmupSupertonicSamplesAsync(speedValue, steps, pitchValue, volumeValue, pauseValue);
				if (speedValue == requestedSampleWarmupSpeed && steps == requestedSampleWarmupSteps && pitchValue == requestedSampleWarmupPitch && volumeValue == requestedSampleWarmupVolume && pauseValue == requestedSampleWarmupPause)
				{
					break;
				}
			}
		}
		catch
		{
		}
		finally
		{
			sampleWarmupRunning = false;
			if (!base.IsDisposed && labelProgressStatus != null && labelProgressStatus.Text.StartsWith("샘플 미리 준비"))
			{
				labelProgressStatus.Text = "";
			}
		}
	}

	private async Task WarmupSupertonicSamplesAsync(int speedValue, int steps, int pitchValue, int volumeValue, int pauseValue)
	{
		if (speedValue <= 0 || steps <= 0)
		{
			return;
		}
		Directory.CreateDirectory(GetSampleDirectory());
		List<string> list = supertonicSampleVoices.Where((string voice) => !File.Exists(GetSamplePath("supertonic_stable", voice, speedValue, steps, pitchValue, volumeValue, pauseValue))).ToList();
		if (list.Count == 0)
		{
			return;
		}
		labelProgressStatus.Text = $"샘플 미리 준비 중... 0/{list.Count}";
		await EnsureSupertonicServerAsync();
		double speed = (double)speedValue / 100.0;
		double volumeFactor = (double)volumeValue / 100.0;
		for (int i = 0; i < list.Count; i++)
		{
			if (!IsSupertonicSelected())
			{
				break;
			}
			if (speedValue != requestedSampleWarmupSpeed)
			{
				break;
			}
			if (steps != requestedSampleWarmupSteps)
			{
				break;
			}
			if (pitchValue != requestedSampleWarmupPitch)
			{
				break;
			}
			if (volumeValue != requestedSampleWarmupVolume)
			{
				break;
			}
			if (pauseValue != requestedSampleWarmupPause)
			{
				break;
			}
			string text = list[i];
			string samplePath = GetSamplePath("supertonic_stable", text, speedValue, steps, pitchValue, volumeValue, pauseValue);
			if (!File.Exists(samplePath))
			{
				string baseSamplePath = GetBaseSamplePath("supertonic_stable", text, steps, pauseValue);
				if (!File.Exists(baseSamplePath))
				{
					string path = baseSamplePath;
					WriteSampleFile(path, await CreateSupertonicSampleBaseAsync(text, steps, pauseValue));
				}
				byte[] wav = File.ReadAllBytes(baseSamplePath);
				wav = ApplyVoicePostProcessingToWav(wav, speed, pitchValue, volumeFactor);
				WriteSampleFile(samplePath, wav);
			}
			labelProgressStatus.Text = $"샘플 미리 준비 중... {i + 1}/{list.Count}";
		}
	}

	private async void buttonPlaySample_Click(object sender, EventArgs e)
	{
		object selectedItem = comboBoxVoice.SelectedItem;
		if (!(selectedItem is VoiceItem voiceItem))
		{
			MessageBox.Show("샘플을 재생할 음성을 먼저 선택해주세요.", "음성 선택", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			return;
		}
		bool voxSample = !IsSupertonicSelected();
		VoxGenerationSnapshot? voxSnapshot = null;
		if (voxSample)
		{
			try
			{
				voxSnapshot = CaptureVoxGenerationSnapshot("", "샘플 음성입니다. 안녕하세요.");
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.Message, "참조 WAV 필요", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
				return;
			}
		}
		bool sampleStarted = false;
		CancellationToken sampleToken = CancellationToken.None;
		if (voxSample)
		{
			generationCancellation?.Dispose();
			generationCancellation = new CancellationTokenSource();
			sampleToken = generationCancellation.Token;
			generationInProgress = true;
			SetVoxGenerationControlsLocked(true);
			buttonStopGenerated.Enabled = true;
			buttonStopGenerated.Text = "생성 취소";
		}
		string originalText = buttonPlaySample.Text;
		buttonPlaySample.Enabled = false;
		buttonPlaySample.Text = "생성 중";
		labelProgressStatus.Text = "샘플 생성 중...";
		try
		{
			string engineName = voxSample ? "voxcpm2" : "supertonic_stable";
			int speedValue = voxSample ? (int)Math.Round(voxSnapshot!.SpeedFactor * 100.0) : (trackBarSpeed?.Value ?? 105);
			int steps = voxSample ? voxSnapshot!.InferenceSteps : GetSelectedSteps();
			int pitchValue = voxSample ? 0 : (trackBarPitch?.Value ?? 0);
			int volumeValue = voxSample ? (int)Math.Round(voxSnapshot!.VolumeFactor * 100.0) : (trackBarVolume?.Value ?? 100);
			int pauseValue = voxSample ? (int)Math.Round(voxSnapshot!.SilenceSeconds * 100.0) : (trackBarPause?.Value ?? 25);
			string sampleVoiceKey = voiceItem.VoiceId;
			if (voxSample && string.Equals(voxSnapshot!.ProfileId, "vox_clone", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(voxSnapshot.ReferencePath))
			{
				sampleVoiceKey += "_" + Path.GetFileNameWithoutExtension(voxSnapshot.ReferencePath);
			}
			string samplePath = GetSamplePath(engineName, sampleVoiceKey, speedValue, steps, pitchValue, volumeValue, pauseValue);
			if (!string.Equals(voiceItem.VoiceId, "vox_clone", StringComparison.Ordinal))
			{
				string bundledSamplePath = GetBundledSamplePath(voxSample, voiceItem.VoiceId);
				if (IsUsableBundledSample(bundledSamplePath))
				{
					samplePath = bundledSamplePath;
				}
			}
			if (!File.Exists(samplePath))
			{
				Directory.CreateDirectory(GetSampleDirectory());
				byte[] wav;
				if (!voxSample)
				{
					await EnsureSupertonicServerAsync();
					double selectedSpeed = GetSelectedSpeed();
					string baseSamplePath = GetBaseSamplePath(engineName, voiceItem.VoiceId, steps, pauseValue);
					if (!File.Exists(baseSamplePath))
					{
						string path = baseSamplePath;
						WriteSampleFile(path, await CreateSupertonicSampleBaseAsync(voiceItem.VoiceId, steps, pauseValue));
					}
					wav = File.ReadAllBytes(baseSamplePath);
					wav = ApplyVoicePostProcessingToWav(wav, selectedSpeed, pitchValue, (double)volumeValue / 100.0);
				}
				else
				{
					await EnsureVoxServerAsync();
					wav = await CallVoxTtsApi(PrepareTextForVox(voxSnapshot!.Text), voxSnapshot.ProfileId, voxSnapshot.ReferencePath, voxSnapshot.InferenceSteps, voxSnapshot.Seed, sampleToken);
					ValidateVoxOutput(wav);
					wav = ApplyVoicePostProcessingToWav(wav, voxSnapshot.SpeedFactor, 0, voxSnapshot.VolumeFactor);
				}
				WriteSampleFile(samplePath, wav);
			}
			soundPlayer.Stop();
			soundPlayer.SoundLocation = samplePath;
			soundPlayer.Play();
			sampleStarted = true;
			buttonStopGenerated.Enabled = true;
		}
		catch (OperationCanceledException) when (sampleToken.IsCancellationRequested)
		{
			labelProgressStatus.Text = "샘플 생성이 취소되었습니다.";
		}
		catch (Exception ex)
		{
			string text2 = ex.Message;
			if (ex.InnerException != null && !string.IsNullOrWhiteSpace(ex.InnerException.Message))
			{
				text2 = text2 + "\n" + ex.InnerException.Message;
			}
			MessageBox.Show("샘플 생성 중 오류가 발생했습니다: " + text2, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
		finally
		{
			if (voxSample)
			{
				generationInProgress = false;
				generationCancellation?.Dispose();
				generationCancellation = null;
				SetVoxGenerationControlsLocked(false);
				buttonStopGenerated.Text = "정지";
				UpdateModelStatusLabel();
				buttonStopGenerated.Enabled = sampleStarted || (!string.IsNullOrWhiteSpace(lastGeneratedAudioPath) && File.Exists(lastGeneratedAudioPath));
			}
			buttonPlaySample.Enabled = true;
			buttonPlaySample.Text = originalText;
			labelProgressStatus.Text = "";
		}
	}

	private void buttonOpenFolder_Click(object sender, EventArgs e)
	{
		try
		{
			if (!Directory.Exists(savedAudioPath))
			{
				Directory.CreateDirectory(savedAudioPath);
			}
			Process.Start("explorer.exe", savedAudioPath);
		}
		catch (Exception ex)
		{
			MessageBox.Show("오디오 폴더를 여는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	private void buttonSelectFolder_Click(object sender, EventArgs e)
	{
		using FolderBrowserDialog folderBrowserDialog = new FolderBrowserDialog();
		if (folderBrowserDialog.ShowDialog() == DialogResult.OK && !string.IsNullOrWhiteSpace(folderBrowserDialog.SelectedPath))
		{
			savedAudioPath = folderBrowserDialog.SelectedPath;
			textBoxSaveDirectory.Text = savedAudioPath;
			MessageBox.Show("오디오 저장 경로가 변경되었습니다.", "경로 변경", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
		}
	}

	private void buttonOpenBlog_Click(object sender, EventArgs e)
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = "https://x.com/kajjonku?s=11&t=blFT4EtsUNPJQH7sRqK9Cw",
				UseShellExecute = true
			});
		}
		catch (Exception ex)
		{
			MessageBox.Show("개발자 X를 여는 중 오류가 발생했습니다: " + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}


	private List<string> SplitTextIntoChunks(string text, int maxLength)
	{
		List<string> list = new List<string>();
		if (string.IsNullOrWhiteSpace(text))
		{
			return list;
		}
		StringBuilder stringBuilder = new StringBuilder();
		StringBuilder stringBuilder2 = new StringBuilder();
		int i = 0;
		while (i < text.Length)
		{
			char c = text[i];
			stringBuilder2.Append(c);
			if (IsSentenceEnding(c))
			{
				int endPos = i + 1;
				while (endPos < text.Length && IsClosingQuoteOrBracket(text[endPos]))
				{
					stringBuilder2.Append(text[endPos]);
					endPos++;
					i++;
				}
				AddSentenceToChunks(list, stringBuilder, stringBuilder2.ToString().Trim(), maxLength);
				stringBuilder2.Clear();
			}
			i++;
		}
		string remainder = stringBuilder2.ToString().Trim();
		AddSentenceToChunks(list, stringBuilder, remainder, maxLength);
		if (stringBuilder.Length > 0)
		{
			string final = stringBuilder.ToString().Trim();
			if (!string.IsNullOrWhiteSpace(final))
			{
				list.Add(final);
			}
		}
		return list;
	}

	private bool IsSentenceEnding(char c)
	{
		if (c == '.' || c == '!' || c == '?' || c == '。' || c == '！' || c == '？' || c == '\n' || c == ';')
		{
			return true;
		}
		if (c == '다' || c == '요' || c == '까' || c == '네' || c == '죠' || c == '습')
		{
			return true;
		}
		return false;
	}

	private bool IsClosingQuoteOrBracket(char c)
	{
		return c == '"' || c == '\'' || c == ')' || c == ']' || c == (char)8221 || c == (char)8217 || c == (char)65289 || c == (char)12301 || c == (char)12303;
	}

	private void AddSentenceToChunks(List<string> chunks, StringBuilder current, string sentence, int maxLength)
	{
		if (string.IsNullOrWhiteSpace(sentence))
		{
			return;
		}
		foreach (string item in SplitLongSentence(sentence, maxLength))
		{
			if (string.IsNullOrWhiteSpace(item))
			{
				continue;
			}
			string text = ((current.Length == 0) ? item : (current.ToString() + " " + item));
			if (text.Length <= maxLength)
			{
				current.Clear();
				current.Append(text);
				continue;
			}
			if (current.Length > 0)
			{
				string chunk = current.ToString().Trim();
				if (!string.IsNullOrWhiteSpace(chunk))
				{
					chunks.Add(chunk);
				}
				current.Clear();
			}
			current.Append(item);
		}
	}

	private List<string> SplitLongSentence(string sentence, int maxLength)
	{
		List<string> list = new List<string>();
		string text = sentence.Trim();
		while (text.Length > maxLength)
		{
			int num = FindChunkCut(text, maxLength);
			string chunk = text.Substring(0, num).Trim();
			if (!string.IsNullOrWhiteSpace(chunk))
			{
				list.Add(chunk);
			}
			text = text.Substring(num).Trim();
		}
		if (!string.IsNullOrWhiteSpace(text))
		{
			list.Add(text);
		}
		return list;
	}

	private int FindChunkCut(string text, int maxLength)
	{
		int upper = Math.Min(maxLength, text.Length - 1);
		for (int num = upper; num >= maxLength / 2; num--)
		{
			if (text[num] == ',' || text[num] == '，' || text[num] == '、')
			{
				return num + 1;
			}
		}
		for (int num = upper; num >= maxLength / 2; num--)
		{
			if (char.IsWhiteSpace(text[num]))
			{
				return num + 1;
			}
		}
		return Math.Min(maxLength, text.Length);
	}


	private byte[] ApplySpeedToPcm(byte[] pcmData, double speedFactor)
	{
		if (pcmData == null || pcmData.Length < 4)
		{
			return pcmData;
		}
		if (Math.Abs(speedFactor - 1.0) < 0.001)
		{
			return pcmData;
		}
		int num = pcmData.Length / 2;
		if (num < 2048)
		{
			return pcmData;
		}
		short[] array = new short[num];
		Buffer.BlockCopy(pcmData, 0, array, 0, num * 2);
		short[] array2 = TimeScalePcm(array, speedFactor);
		byte[] array3 = new byte[array2.Length * 2];
		Buffer.BlockCopy(array2, 0, array3, 0, array3.Length);
		return AddTailPadding(array3, 24000);
	}

	private byte[] AddTailPadding(byte[] audioData, int sampleRate)
	{
		if (audioData == null || audioData.Length < 4)
		{
			return audioData;
		}
		int paddingSamples = Math.Max(100, sampleRate / 20);
		int paddingBytes = paddingSamples * 2;
		byte[] padded = new byte[audioData.Length + paddingBytes];
		Array.Copy(audioData, padded, audioData.Length);
		return padded;
	}

	private short[] TimeScalePcm(short[] samples, double speedFactor)
	{
		int num = 960;
		int num2 = 480;
		int num3 = num - num2;
		int num4 = Math.Max(160, (int)Math.Round((double)num3 * speedFactor));
		int num5 = 240;
		if (samples.Length <= num + num4)
		{
			return samples;
		}
		short[] array = new short[(2 + (samples.Length - num) / num4) * num3 + num + num5];
		Array.Copy(samples, 0, array, 0, num);
		int num6 = 0;
		int num7 = num3;
		int num8 = num;
		int num9 = num;
		do
		{
			int num10 = num6 + num4;
			if (num10 + num >= samples.Length)
			{
				break;
			}
			int num11 = FindBestOverlapPosition(samples, array, num10, num7, num, num2, num5);
			CrossfadeFrame(samples, array, num11, num7, num, num2);
			num9 = Math.Max(num9, Math.Min(samples.Length, num11 + num));
			num6 = num10;
			num8 = Math.Max(num8, num7 + num);
			num7 += num3;
		}
		while (num7 + num < array.Length);
		if (num9 < samples.Length)
		{
			int num12 = samples.Length - num9;
			if (num8 + num12 > array.Length)
			{
				Array.Resize(ref array, num8 + num12);
			}
			Array.Copy(samples, num9, array, num8, num12);
			num8 += num12;
		}
		short[] array2 = new short[num8];
		Array.Copy(array, array2, num8);
		return array2;
	}

	private int FindBestOverlapPosition(short[] samples, short[] output, int expectedInput, int outputPosition, int frameSize, int overlap, int searchRadius)
	{
		int num = Math.Max(0, samples.Length - frameSize);
		int num2 = Math.Min(overlap, Math.Min(samples.Length, output.Length - outputPosition));
		if (num2 <= 0)
		{
			return Math.Max(0, Math.Min(expectedInput, num));
		}
		int num3 = Math.Max(0, expectedInput - searchRadius);
		int num4 = Math.Min(num, expectedInput + searchRadius);
		if (num4 < num3)
		{
			return Math.Max(0, Math.Min(expectedInput, num));
		}
		double num5 = double.NegativeInfinity;
		int result = Math.Max(0, Math.Min(expectedInput, num));
		for (int i = num3; i <= num4; i += 8)
		{
			double num6 = 0.0;
			double num7 = 0.0;
			double num8 = 0.0;
			for (int j = 0; j < num2; j += 2)
			{
				double num9 = output[outputPosition + j];
				double num10 = samples[i + j];
				num6 += num9 * num10;
				num7 += num9 * num9;
				num8 += num10 * num10;
			}
			double num11 = num6 / Math.Sqrt(num7 * num8 + 1.0);
			if (num11 > num5)
			{
				num5 = num11;
				result = i;
			}
		}
		return result;
	}

	private void CrossfadeFrame(short[] samples, short[] output, int inputPosition, int outputPosition, int frameSize, int overlap)
	{
		if (inputPosition < 0)
		{
			inputPosition = 0;
		}
		if (outputPosition < 0)
		{
			outputPosition = 0;
		}
		int num = Math.Min(frameSize, Math.Min(samples.Length - inputPosition, output.Length - outputPosition));
		if (num > 0)
		{
			int num2 = Math.Min(overlap, num);
			for (int i = 0; i < num2; i++)
			{
				double num3 = (double)i / (double)num2;
				double num4 = (double)output[outputPosition + i] * (1.0 - num3);
				double num5 = (double)samples[inputPosition + i] * num3;
				output[outputPosition + i] = ClampToShort(num4 + num5);
			}
			for (int j = num2; j < num; j++)
			{
				output[outputPosition + j] = samples[inputPosition + j];
			}
		}
	}

	private short ClampToShort(double value)
	{
		if (value > 32767.0)
		{
			return short.MaxValue;
		}
		if (value < -32768.0)
		{
			return short.MinValue;
		}
		return (short)Math.Round(value);
	}

	private void buttonSaveSettings_Click(object sender, EventArgs e)
	{
		SaveSettings();
	}

	protected override void Dispose(bool disposing)
	{
		base.Dispose(disposing);
	}


	private bool IsHiggsSelected()
	{
		return SelectedEngine == TtsEngineKind.HiggsAudioV3;
	}

	private string GetHiggsRoot()
	{
		return Path.Combine(InternalRoot, "HiggsAudioV3Local");
	}

	private string GetHiggsPersistentSampleCacheDirectory()
	{
		return Path.Combine(GetHiggsRuntimeRoot(), "cache", "samples");
	}

	private string GetHiggsVoiceAnchorCacheDirectory()
	{
		return Path.Combine(GetHiggsRuntimeRoot(), "cache", "voice_anchors");
	}

	private void MigrateLegacyHiggsSampleCache(string persistentDirectory)
	{
		try
		{
			string text = Path.Combine(GetHiggsRoot(), "cache", "samples");
			if (!Directory.Exists(text) || string.Equals(text, persistentDirectory, StringComparison.OrdinalIgnoreCase))
			{
				return;
			}
			string[] files = Directory.GetFiles(text, "*.wav", SearchOption.TopDirectoryOnly);
			foreach (string text2 in files)
			{
				string text3 = Path.Combine(persistentDirectory, Path.GetFileName(text2));
				if (!File.Exists(text3))
				{
					File.Copy(text2, text3, overwrite: false);
				}
			}
		}
		catch (Exception ex)
		{
			AppendHiggsLog("legacy sample cache migration skipped: " + ex.Message);
		}
	}

	private string GetHiggsRuntimeRoot()
	{
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
		string text = Path.Combine(folderPath, "SupertonicVox", "higgs");
		if (HasAnyHiggsServer(text) && File.Exists(Path.Combine(text, "models", "Higgs-Audio-v3-TTS-4B-GGUF", "higgs-audio-v3-tts-4b-q8_0.gguf")))
		{
			return text;
		}
		return Path.Combine(InstallRoot, "HiggsAudioV3");
	}

	private static bool HasAnyHiggsServer(string runtimeRoot)
	{
		if (!File.Exists(Path.Combine(runtimeRoot, "gpu", "audiocpp_server.exe")) && !File.Exists(Path.Combine(runtimeRoot, "cuda", "audiocpp_server.exe")))
		{
			return File.Exists(Path.Combine(runtimeRoot, "cpu", "audiocpp_server.exe"));
		}
		return true;
	}

	private bool IsNvidiaCudaAvailable()
	{
		if (higgsCudaAvailable.HasValue)
		{
			return higgsCudaAvailable.Value;
		}
		try
		{
			using Process process = new Process
			{
				StartInfo = new ProcessStartInfo
				{
					FileName = "nvidia-smi.exe",
					Arguments = "--query-gpu=name,memory.total --format=csv,noheader",
					UseShellExecute = false,
					CreateNoWindow = true,
					RedirectStandardOutput = true,
					RedirectStandardError = true
				}
			};
			process.Start();
			string text = process.StandardOutput.ReadToEnd();
			if (!process.WaitForExit(5000))
			{
				process.Kill(entireProcessTree: true);
			}
			higgsCudaAvailable = process.HasExited && process.ExitCode == 0 && text.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0;
		}
		catch
		{
			higgsCudaAvailable = false;
		}
		return higgsCudaAvailable.Value;
	}

	private (string ServerPath, string Backend) ResolveHiggsRuntimeServer(bool forceCpu)
	{
		string higgsRuntimeRoot = GetHiggsRuntimeRoot();
		if (!forceCpu && IsNvidiaCudaAvailable())
		{
			string[] array = new string[2] { "gpu", "cuda" };
			foreach (string path in array)
			{
				string text = Path.Combine(higgsRuntimeRoot, path, "audiocpp_server.exe");
				if (File.Exists(text))
				{
					return (ServerPath: text, Backend: "cuda");
				}
			}
		}
		string text2 = Path.Combine(higgsRuntimeRoot, "cpu", "audiocpp_server.exe");
		if (File.Exists(text2))
		{
			return (ServerPath: text2, Backend: "cpu");
		}
		throw new FileNotFoundException("Higgs Audio v3 CPU/CUDA server executable not found.", text2);
	}

	private string GetHiggsPreferredBackendLabel()
	{
		try
		{
			return (ResolveHiggsRuntimeServer(forceCpu: false).Backend == "cuda") ? "CUDA GPU" : "CPU";
		}
		catch
		{
			return "Not installed";
		}
	}

	private string GetHiggsModelDirectory()
	{
		return Path.Combine(GetHiggsRuntimeRoot(), "models", "Higgs-Audio-v3-TTS-4B-GGUF");
	}

	private string GetHiggsModelPath()
	{
		return Path.Combine(GetHiggsModelDirectory(), "higgs-audio-v3-tts-4b-q8_0.gguf");
	}

	private string GetHiggsVoiceReferencePath(string voiceId)
	{
		if (string.IsNullOrWhiteSpace(voiceId) || string.Equals(voiceId, "higgs_default", StringComparison.Ordinal))
		{
			return "";
		}
		if (higgsUseLowMemoryReference)
		{
			string text = Path.Combine(GetHiggsRuntimeRoot(), "voices", voiceId + ".lowmem.wav");
			if (File.Exists(text))
			{
				return text;
			}
		}
		return Path.Combine(GetHiggsRuntimeRoot(), "voices", voiceId + ".wav");
	}

	private bool HasHiggsLowMemoryReference(string voiceId)
	{
		if (!string.IsNullOrWhiteSpace(voiceId))
		{
			return File.Exists(Path.Combine(GetHiggsRuntimeRoot(), "voices", voiceId + ".lowmem.wav"));
		}
		return false;
	}

	private void ValidateHiggsVoiceReferenceOrThrow(string voiceId)
	{
		if (!string.IsNullOrWhiteSpace(voiceId) && !string.Equals(voiceId, "higgs_default", StringComparison.Ordinal))
		{
			string higgsVoiceReferencePath = GetHiggsVoiceReferencePath(voiceId);
			if (!File.Exists(higgsVoiceReferencePath))
			{
				throw new FileNotFoundException("Higgs voice reference WAV not found: " + voiceId + ". Please restore the file and try again.", higgsVoiceReferencePath);
			}
			WavData wavData;
			try
			{
				wavData = ReadWavData(File.ReadAllBytes(higgsVoiceReferencePath));
			}
			catch (Exception innerException)
			{
				throw new InvalidDataException("Failed to read Higgs voice reference WAV: " + voiceId + ".", innerException);
			}
			if (wavData.AudioFormat != 1 || wavData.BitsPerSample != 16 || wavData.Channels != 1 || wavData.SampleRate != 24000)
			{
				throw new InvalidDataException($"Higgs voice reference WAV format is incorrect: {voiceId} ({wavData.SampleRate}Hz, {wavData.Channels}ch, {wavData.BitsPerSample}bit, format {wavData.AudioFormat}). PCM16 mono 24kHz required. Path: {higgsVoiceReferencePath}");
			}
			double num = (double)wavData.Data.Length / (double)(wavData.SampleRate * wavData.Channels * (wavData.BitsPerSample / 8));
			if (num < 5.0 || num > 20.0)
			{
				throw new InvalidDataException($"Higgs voice reference WAV duration out of range: {voiceId} ({num:0.###}s, 5-20s required). Path: {higgsVoiceReferencePath}");
			}
		}
	}

	private string GetHiggsReferenceVersion(string referencePath)
	{
		using FileStream inputStream = File.OpenRead(referencePath);
		using SHA256 sHA = SHA256.Create();
		return Convert.ToHexString(sHA.ComputeHash(inputStream)).ToLowerInvariant();
	}

	private string GetHiggsVoiceReferenceText(string voiceId)
	{
		if (string.IsNullOrWhiteSpace(voiceId) || string.Equals(voiceId, "higgs_default", StringComparison.Ordinal))
		{
			return "";
		}
		string voicesPath = Path.Combine(GetHiggsRuntimeRoot(), "voices");
		string textFile = Path.Combine(voicesPath, voiceId + ".txt");
		if (File.Exists(textFile))
		{
			try
			{
				return File.ReadAllText(textFile, Encoding.UTF8).Trim();
			}
			catch
			{
			}
		}
		return "";
	}

	private string GetHiggsLowMemoryReferenceText(string voiceId)
	{
		string referenceText = GetHiggsVoiceReferenceText(voiceId);
		if (!string.IsNullOrWhiteSpace(referenceText) && referenceText.Length > 100)
		{
			return referenceText.Substring(0, 100);
		}
		return referenceText;
	}

	private List<string> GetMissingHiggsFiles()
	{
		List<string> list = new List<string>();
		string higgsRuntimeRoot = GetHiggsRuntimeRoot();
		string higgsModelPath = GetHiggsModelPath();
		if (!HasAnyHiggsServer(higgsRuntimeRoot))
		{
			list.Add("cpu or gpu\\audiocpp_server.exe");
		}
		if (!File.Exists(higgsModelPath) || new FileInfo(higgsModelPath).Length != 5095354048L)
		{
			list.Add("models\\Higgs-Audio-v3-TTS-4B-GGUF\\higgs-audio-v3-tts-4b-q8_0.gguf");
		}
		return list;
	}

	private void ValidateHiggsInstallationOrThrow()
	{
		List<string> missingHiggsFiles = GetMissingHiggsFiles();
		if (missingHiggsFiles.Count > 0)
		{
			throw new FileNotFoundException("Higgs Audio v3 installation incomplete. Missing or size mismatch: " + string.Join(", ", missingHiggsFiles));
		}
	}

	private int FindAvailableHiggsPort()
	{
		for (int i = 8088; i <= 8098; i++)
		{
			if (IsPortAvailable(i))
			{
				return i;
			}
		}
		throw new Exception("No available port for Higgs Audio v3 server. Check ports 8088-8098.");
	}

	private string WriteHiggsServerConfig(int port, string backend)
	{
		string text = Path.Combine(GetHiggsRuntimeRoot(), "server_higgs_integrated.json");
		JObject val = JObject.FromObject((object)new
		{
			host = "127.0.0.1",
			port = port,
			backend = backend,
			device = 0,
			threads = Math.Max(1, Math.Min(19, Environment.ProcessorCount - 1)),
			lazy_load = true,
			busy_timeout_ms = 1800000,
			models = new[]
			{
				new
				{
					id = "higgs-audio-tts",
					family = "higgs_audio_tts",
					path = GetHiggsModelPath(),
					task = "tts",
					mode = "offline",
					lazy = true
				}
			}
		});
		File.WriteAllText(text, ((object)val).ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
		return text;
	}

	private async Task<bool> IsHiggsHealthyAsync(int port)
	{
		try
		{
			using HttpClientHandler handler = new HttpClientHandler
			{
				UseProxy = false
			};
			HttpClient client = new HttpClient(handler)
			{
				Timeout = TimeSpan.FromSeconds(2.0)
			};
			try
			{
				using HttpResponseMessage health = await client.GetAsync($"http://127.0.0.1:{port}/health");
				if (!health.IsSuccessStatusCode)
				{
					return false;
				}
				using HttpResponseMessage models = await client.GetAsync($"http://127.0.0.1:{port}/v1/models");
				if (!models.IsSuccessStatusCode)
				{
					return false;
				}
				return (await models.Content.ReadAsStringAsync()).Contains("higgs-audio-tts", StringComparison.OrdinalIgnoreCase);
			}
			finally
			{
				client?.Dispose();
			}
		}
		catch
		{
			return false;
		}
	}

	private void StopStaleHiggsRuntimeServers()
	{
		string value = Path.GetFullPath(GetHiggsRuntimeRoot()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
		Process[] processesByName = Process.GetProcessesByName("audiocpp_server");
		foreach (Process process in processesByName)
		{
			try
			{
				string text = process.MainModule?.FileName;
				if (!string.IsNullOrWhiteSpace(text) && Path.GetFullPath(text).StartsWith(value, StringComparison.OrdinalIgnoreCase))
				{
					process.Kill(entireProcessTree: true);
					process.WaitForExit(10000);
				}
			}
			catch
			{
			}
			finally
			{
				process.Dispose();
			}
		}
	}

	private async Task EnsureHiggsServerAsync()
	{
		bool flag = higgsProcess != null && !higgsProcess.HasExited && higgsPort > 0;
		if (flag)
		{
			flag = await IsHiggsHealthyAsync(higgsPort);
		}
		if (!flag)
		{
			StopHiggsServer();
			StopSupertonicServer();
			if (!StopVoxServer())
			{
				throw new Exception("VoxCPM2 server did not stop; cannot start Higgs Audio v3.");
			}
			ValidateHiggsInstallationOrThrow();
			string runtimeRoot = GetHiggsRuntimeRoot();
			(string ServerPath, string Backend) runtime = ResolveHiggsRuntimeServer(higgsForceCpuForSession);
			try
			{
				await StartHiggsRuntimeAsync(runtime, runtimeRoot);
			}
			catch (Exception ex) when ((generationCancellation == null || !generationCancellation.IsCancellationRequested) && string.Equals(runtime.Backend, "cuda", StringComparison.OrdinalIgnoreCase) && File.Exists(Path.Combine(runtimeRoot, "cpu", "audiocpp_server.exe")))
			{
				AppendHiggsLog("CUDA runtime startup failed; switching to CPU fallback once. " + ex.Message);
				StopHiggsServer();
				higgsForceCpuForSession = true;
				(string, string) runtime2 = ResolveHiggsRuntimeServer(forceCpu: true);
				await StartHiggsRuntimeAsync(runtime2, runtimeRoot);
			}
		}
	}

	private async Task StartHiggsRuntimeAsync((string ServerPath, string Backend) runtime, string runtimeRoot)
	{
		string item = runtime.ServerPath;
		int portToUse = FindAvailableHiggsPort();
		string text = WriteHiggsServerConfig(portToUse, runtime.Backend);
		ProcessStartInfo startInfo = new ProcessStartInfo
		{
			FileName = item,
			Arguments = "--config \"" + text + "\"",
			WorkingDirectory = runtimeRoot,
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true
		};
		higgsProcess = new Process
		{
			StartInfo = startInfo
		};
		higgsProcess.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
		{
			AppendHiggsLog(e.Data);
		};
		higgsProcess.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
		{
			AppendHiggsLog(e.Data);
		};
		higgsProcess.Start();
		higgsProcess.BeginOutputReadLine();
		higgsProcess.BeginErrorReadLine();
		higgsPort = portToUse;
		higgsActiveBackend = runtime.Backend;
		AppendHiggsLog("starting Higgs runtime backend=" + runtime.Backend + ", server=" + item);
		DateTime deadline = DateTime.Now.AddMinutes(3.0);
		while (DateTime.Now < deadline)
		{
			generationCancellation?.Token.ThrowIfCancellationRequested();
			if (await IsHiggsHealthyAsync(portToUse))
			{
				return;
			}
			if (higgsProcess.HasExited)
			{
				throw new Exception($"Higgs Audio v3 server exited during startup (exit code {higgsProcess.ExitCode}). Check logs\\higgs_server_integrated.log.");
			}
			await Task.Delay(1000);
		}
		throw new TimeoutException("Higgs Audio v3 server did not become ready within 3 minutes.");
	}

	private void AppendHiggsLog(string line)
	{
		if (string.IsNullOrWhiteSpace(line))
		{
			return;
		}
		try
		{
			string path = Path.Combine(GetHiggsRuntimeRoot(), "logs", "higgs_server_integrated.log");
			Directory.CreateDirectory(Path.GetDirectoryName(path));
			lock (higgsLogLock)
			{
				File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + line + Environment.NewLine, Encoding.UTF8);
			}
		}
		catch
		{
		}
	}

	private async Task<byte[]> CallHiggsTtsApi(string text, string voiceId, int seed, string quality, CancellationToken cancellationToken, int maxTokensCap = 0, string voiceReferenceOverride = null, string referenceTextOverride = null)
	{
		if (string.IsNullOrWhiteSpace(quality))
		{
			quality = cachedHiggsQuality;
		}
		int maxTokens = ((quality == "빠른 생성") ? 1200 : ((quality == "균형") ? 1600 : 2048));
		if (maxTokensCap > 0)
		{
			maxTokens = Math.Min(maxTokens, maxTokensCap);
		}
		double temperature = ((quality == "빠른 생성") ? 0.58 : ((quality == "균형") ? 0.62 : 0.66));
		int topK = ((quality == "빠른 생성") ? 16 : ((quality == "균형") ? 20 : 24));
		double topP = ((quality == "빠른 생성") ? 0.72 : ((quality == "균형") ? 0.76 : 0.8));
		string voiceReference = (string.IsNullOrWhiteSpace(voiceReferenceOverride) ? GetHiggsVoiceReferencePath(voiceId) : voiceReferenceOverride);
		string referenceText = referenceTextOverride;
		if (!string.IsNullOrWhiteSpace(voiceReference))
		{
			if (string.IsNullOrWhiteSpace(voiceReferenceOverride))
			{
				ValidateHiggsVoiceReferenceOrThrow(voiceId);
				referenceText = (higgsUseLowMemoryReference ? GetHiggsLowMemoryReferenceText(voiceId) : GetHiggsVoiceReferenceText(voiceId));
			}
			else if (!File.Exists(voiceReference))
			{
				throw new FileNotFoundException("Higgs voice anchor WAV not found.", voiceReference);
			}
		}
		using HttpClientHandler handler = new HttpClientHandler
		{
			UseProxy = false
		};
		HttpClient client = new HttpClient(handler)
		{
			Timeout = TimeSpan.FromMinutes(30.0)
		};
		try
		{
			for (int attempt = 0; attempt < 2; attempt++)
			{
				int attemptMaxTokens = ((attempt == 0) ? maxTokens : Math.Min(maxTokens * 2, 4096));
				JObject val = JObject.FromObject((object)new
				{
					model = "higgs-audio-tts",
					input = text,
					language = "ko",
					seed = seed,
					max_tokens = attemptMaxTokens,
					temperature = temperature,
					top_k = topK,
					top_p = topP,
					response_format = "wav"
				});
				if (!string.IsNullOrWhiteSpace(voiceReference))
				{
					val["voice_ref"] = voiceReference;
					if (!string.IsNullOrWhiteSpace(referenceText))
					{
						val["reference_text"] = referenceText;
					}
				}
				using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{higgsPort}/v1/audio/speech")
				{
					Content = new StringContent(((object)val).ToString(), Encoding.UTF8, "application/json")
				};
				using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
				if (response.IsSuccessStatusCode)
				{
					return await response.Content.ReadAsByteArrayAsync(cancellationToken);
				}
				string text2 = await response.Content.ReadAsStringAsync(cancellationToken);
				bool flag = text2.IndexOf("max_tokens before EOC", StringComparison.OrdinalIgnoreCase) >= 0;
				if (attempt == 0 && flag && attemptMaxTokens < 4096)
				{
					AppendHiggsLog($"max_tokens before EOC detected: retry once ({attemptMaxTokens} -> {Math.Min(attemptMaxTokens * 2, 4096)})");
					continue;
				}
				throw new Exception($"Higgs Audio v3 TTS error: {response.StatusCode}\n{text2}");
			}
			throw new InvalidOperationException("Higgs Audio v3 TTS retry limit exceeded.");
		}
		finally
		{
			client?.Dispose();
		}
	}

	private async Task<(string ReferencePath, string ReferenceText)> EnsureHiggsVoiceAnchorAsync(string voiceId, int seed, string quality, CancellationToken cancellationToken)
	{
		string higgsVoiceReferencePath = GetHiggsVoiceReferencePath(voiceId);
		string value = "model-default";
		if (!string.IsNullOrWhiteSpace(higgsVoiceReferencePath))
		{
			ValidateHiggsVoiceReferenceOrThrow(voiceId);
			value = GetHiggsReferenceVersion(higgsVoiceReferencePath);
		}
		string higgsVoiceAnchorCacheDirectory = GetHiggsVoiceAnchorCacheDirectory();
		Directory.CreateDirectory(higgsVoiceAnchorCacheDirectory);
		string anchorToken = ShortHash($"{"higgs-voice-anchor-v1"}|voice={voiceId}|seed={seed}|quality={quality}|ref={value}|text={"안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다."}");
		string anchorPath = Path.Combine(higgsVoiceAnchorCacheDirectory, $"anchor_{voiceId}_{anchorToken}.wav");
		if (File.Exists(anchorPath))
		{
			try
			{
				ValidateHiggsOutput(File.ReadAllBytes(anchorPath));
				return (ReferencePath: anchorPath, ReferenceText: "안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.");
			}
			catch
			{
				try
				{
					File.Delete(anchorPath);
				}
				catch
				{
				}
			}
		}
		labelProgressStatus.Text = "Creating Higgs voice anchor profile...";
		byte[] array = await CallHiggsTtsApi("안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.", voiceId, seed, quality, cancellationToken, 1024);
		ValidateHiggsOutput(array, validateDuration: true);
		string text = anchorPath + ".tmp";
		File.WriteAllBytes(text, array);
		File.Move(text, anchorPath, overwrite: true);
		AppendHiggsLog($"persistent voice continuity anchor created: {voiceId} ({anchorToken})");
		return (ReferencePath: anchorPath, ReferenceText: "안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.");
	}

	private void ValidateHiggsOutput(byte[] wav, bool validateDuration = false)
	{
		if (wav == null || wav.Length < 44)
		{
			throw new Exception("Higgs Audio v3 returned empty WAV.");
		}
		WavData wavData = ReadWavData(wav);
		if (wavData.AudioFormat != 1 || wavData.BitsPerSample != 16 || wavData.Channels != 1 || wavData.SampleRate != 24000 || wavData.Data == null || wavData.Data.Length == 0)
		{
			throw new Exception($"Higgs Audio v3 output format incorrect: {wavData.SampleRate}Hz, {wavData.Channels}ch, {wavData.BitsPerSample}bit");
		}
		if (validateDuration)
		{
			double durationSeconds = (double)wavData.Data.Length / (double)(wavData.SampleRate * wavData.Channels * (wavData.BitsPerSample / 8));
			if (durationSeconds < 3.0 || durationSeconds > 8.0)
			{
				throw new Exception($"Higgs Audio v3 anchor duration out of range: {durationSeconds:0.###}s (3-8s required)");
			}
		}
	}

	private static bool IsHiggsMemoryAllocationFailure(Exception ex)
	{
		string text = ex?.ToString() ?? "";
		if (text.IndexOf("failed to allocate", StringComparison.OrdinalIgnoreCase) < 0 && text.IndexOf("out of memory", StringComparison.OrdinalIgnoreCase) < 0 && text.IndexOf("not enough memory", StringComparison.OrdinalIgnoreCase) < 0)
		{
			return text.IndexOf("commitment limit", StringComparison.OrdinalIgnoreCase) >= 0;
		}
		return true;
	}

	private bool HasRecentHiggsMemoryAllocationFailure()
	{
		try
		{
			string path = Path.Combine(GetHiggsRuntimeRoot(), "logs", "higgs_server_integrated.log");
			if (!File.Exists(path) || File.GetLastWriteTimeUtc(path) < DateTime.UtcNow.AddMinutes(-5.0))
			{
				return false;
			}
			string text = File.ReadAllText(path);
			int startIndex = Math.Max(0, text.Length - 12000);
			string text2 = text.Substring(startIndex);
			return text2.IndexOf("failed to allocate buffer", StringComparison.OrdinalIgnoreCase) >= 0 || text2.IndexOf("commitment limit", StringComparison.OrdinalIgnoreCase) >= 0;
		}
		catch
		{
			return false;
		}
	}

	private static ulong GetAvailableCommitBytes()
	{
		try
		{
			MemoryStatusEx memoryStatusEx = new MemoryStatusEx();
			return GlobalMemoryStatusEx(memoryStatusEx) ? memoryStatusEx.ullAvailPageFile : ulong.MaxValue;
		}
		catch
		{
			return ulong.MaxValue;
		}
	}

	private static bool IsFemaleHiggsVoice(string voiceId)
	{
		return voiceId switch
		{
			"vox_news_f" => true,
			"vox_calm_f" => true,
			"vox_emotive_f" => true,
			_ => voiceId?.EndsWith("_f", StringComparison.OrdinalIgnoreCase) ?? false,
		};
	}

	private async Task<byte[]> GenerateSupertonicEmergencyFallbackAsync(string text, string higgsVoiceId, double speed, double volume, double silenceDuration, CancellationToken cancellationToken)
	{
		AppendHiggsLog("Higgs memory safety fallback: switching this request to Supertonic");
		labelProgressStatus.Text = "Memory safety mode: generating with Supertonic...";
		buttonGenerateAudio.Text = "Safe fallback generation...";
		StopHiggsServer();
		GC.Collect();
		GC.WaitForPendingFinalizers();
		await Task.Delay(500, cancellationToken);
		await EnsureSupertonicServerAsync();
		string fallbackVoice = (IsFemaleHiggsVoice(higgsVoiceId) ? "F1" : "M1");
		string text2 = PrepareTextForSupertonic(text);
		List<string> chunks = SplitTextIntoChunks(text2, 10000);
		if (chunks.Count == 0)
		{
			throw new InvalidDataException("No text to generate with fallback engine.");
		}
		List<byte[]> wavs = new List<byte[]>();
		for (int i = 0; i < chunks.Count; i++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			labelProgressStatus.Text = $"Memory safety mode generation... ({i + 1}/{chunks.Count})";
			List<byte[]> list = wavs;
			list.Add(await CallSupertonicTtsApi(chunks[i], fallbackVoice, 1.0, Math.Max(GetSelectedSteps(), 10), silenceDuration));
		}
		byte[] array = ((wavs.Count == 1) ? wavs[0] : MergeWavFiles(wavs));
		if (Math.Abs(speed - 1.0) >= 0.01 || Math.Abs(volume - 1.0) >= 0.01)
		{
			array = ApplyVoicePostProcessingToWav(array, speed, 0, volume);
		}
		return array;
	}

	private async Task<byte[]> GenerateHiggsWavAsync(string text, string voiceId, int seed, string quality, double speed, double volume, double silenceDuration, bool updateGenerateButtonText, CancellationToken cancellationToken)
	{
		higgsMemoryRecoveryAttempted = false;
		higgsForceCpuForSession = false;
		higgsUseLowMemoryReference = HasHiggsLowMemoryReference(voiceId);
		cancellationToken.ThrowIfCancellationRequested();
		await EnsureHiggsServerAsync();
		cancellationToken.ThrowIfCancellationRequested();
		string text2 = PrepareTextForVox(text);
		List<string> chunks = SplitTextIntoChunks(text2, 200);
		if (chunks.Count == 0)
		{
			throw new InvalidDataException("No text to generate after Higgs preprocessing.");
		}
		bool isSampleRequest = string.Equals(text2.Trim(), "안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.", StringComparison.Ordinal);
		(string ReferencePath, string ReferenceText) anchor;
		if (!isSampleRequest)
		{
			string higgsVoiceReferencePath = GetHiggsVoiceReferencePath(voiceId);
			if (!string.IsNullOrWhiteSpace(higgsVoiceReferencePath))
			{
				ValidateHiggsVoiceReferenceOrThrow(voiceId);
				anchor = (ReferencePath: higgsVoiceReferencePath, ReferenceText: higgsUseLowMemoryReference ? GetHiggsLowMemoryReferenceText(voiceId) : GetHiggsVoiceReferenceText(voiceId));
			}
			else
			{
				anchor = await EnsureHiggsVoiceAnchorAsync(voiceId, seed, quality, cancellationToken);
			}
		}
		else
		{
			anchor = await EnsureHiggsVoiceAnchorAsync(voiceId, seed, quality, cancellationToken);
		}
		if (isSampleRequest)
		{
			byte[] array = File.ReadAllBytes(anchor.ReferencePath);
			if (Math.Abs(speed - 1.0) >= 0.01 || Math.Abs(volume - 1.0) >= 0.01)
			{
				labelProgressStatus.Text = "Applying speed/volume...";
				array = ApplyVoicePostProcessingToWav(array, speed, 0, volume);
			}
			ValidateHiggsOutput(array);
			return array;
		}
		List<byte[]> wavs = new List<byte[]>();
		for (int i = 0; i < chunks.Count; i++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (updateGenerateButtonText)
			{
				buttonGenerateAudio.Text = $"Higgs generating... ({i + 1}/{chunks.Count})";
			}
			string value = (string.Equals(higgsActiveBackend, "cuda", StringComparison.OrdinalIgnoreCase) ? "CUDA GPU" : "CPU");
			labelProgressStatus.Text = $"Higgs Audio v3 {value} generating... ({i + 1}/{chunks.Count})";
			byte[] wav;
			try
			{
				wav = await CallHiggsTtsApi(chunks[i], voiceId, seed, quality, cancellationToken, 0, anchor.ReferencePath, anchor.ReferenceText);
			}
			catch (Exception ex) when (!cancellationToken.IsCancellationRequested && !higgsMemoryRecoveryAttempted && IsHiggsMemoryAllocationFailure(ex))
			{
				higgsMemoryRecoveryAttempted = true;
				AppendHiggsLog("memory allocation failure detected; restarting patched low-memory runtime once");
				labelProgressStatus.Text = "Higgs memory cleanup and auto-retry...";
				StopHiggsServer();
				GC.Collect();
				GC.WaitForPendingFinalizers();
				await Task.Delay(1500, cancellationToken);
				await EnsureHiggsServerAsync();
				wav = await CallHiggsTtsApi(chunks[i], voiceId, seed, quality, cancellationToken, 1024, anchor.ReferencePath, anchor.ReferenceText);
			}
			cancellationToken.ThrowIfCancellationRequested();
			ValidateHiggsOutput(wav);
			wavs.Add(wav);
		}
		cancellationToken.ThrowIfCancellationRequested();
		byte[] array2 = ((wavs.Count == 1) ? wavs[0] : MergeWavFilesWithSilence(wavs, silenceDuration));
		if (Math.Abs(speed - 1.0) >= 0.01 || Math.Abs(volume - 1.0) >= 0.01)
		{
			labelProgressStatus.Text = "Applying speed/volume...";
			array2 = ApplyVoicePostProcessingToWav(array2, speed, 0, volume);
		}
		ValidateHiggsOutput(array2);
		return array2;
	}

	private async Task PlayHiggsGeneratedSampleAsync(VoiceItem voice)
	{
		generationCancellation?.Dispose();
		generationCancellation = new CancellationTokenSource();
		CancellationToken cancellationToken = generationCancellation.Token;
		generationInProgress = true;
		SetVoxGenerationControlsLocked(locked: true);
		buttonPlaySample.Enabled = false;
		buttonStopGenerated.Enabled = true;
		buttonStopGenerated.Text = "Cancel generation";
		progressBarTts.Style = ProgressBarStyle.Marquee;
		try
		{
			string text = comboBoxQuality?.SelectedItem?.ToString() ?? cachedHiggsQuality;
			int num = trackBarSpeed?.Value ?? cachedHiggsSpeed;
			int num2 = trackBarVolume?.Value ?? cachedHiggsVolume;
			int num3 = trackBarPause?.Value ?? cachedHiggsPause;
			int num4 = cachedHiggsSeed;
			string value = comboBoxTonePreset?.SelectedItem?.ToString() ?? cachedHiggsTone;
			higgsUseLowMemoryReference = HasHiggsLowMemoryReference(voice.VoiceId);
			string higgsVoiceReferencePath = GetHiggsVoiceReferencePath(voice.VoiceId);
			string value2 = "model-default";
			if (!string.IsNullOrWhiteSpace(higgsVoiceReferencePath))
			{
				ValidateHiggsVoiceReferenceOrThrow(voice.VoiceId);
				value2 = GetHiggsReferenceVersion(higgsVoiceReferencePath);
			}
			string higgsPersistentSampleCacheDirectory = GetHiggsPersistentSampleCacheDirectory();
			Directory.CreateDirectory(higgsPersistentSampleCacheDirectory);
			MigrateLegacyHiggsSampleCache(higgsPersistentSampleCacheDirectory);
			string value3 = ShortHash($"{"higgs-sample-v6-continuity-anchor"}|voice={voice.VoiceId}|speed={num}|volume={num2}|pause={num3}|quality={text}|seed={num4}|tone={value}|ref-version={value2}");
			string samplePath = Path.Combine(higgsPersistentSampleCacheDirectory, $"higgs_{voice.VoiceId}_{value3}.wav");
			if (File.Exists(samplePath))
			{
				try
				{
					ValidateHiggsOutput(File.ReadAllBytes(samplePath));
				}
				catch
				{
					try
					{
						File.Delete(samplePath);
					}
					catch
					{
					}
				}
			}
			if (!File.Exists(samplePath))
			{
				labelProgressStatus.Text = $"Higgs generating sample... (speed {num}%)";
				byte[] bytes = await GenerateHiggsWavAsync("안녕하세요. 현재 선택한 음성과 배속으로 만든 실제 합성 샘플입니다.", voice.VoiceId, num4, text, (double)num / 100.0, (double)num2 / 100.0, (double)num3 / 100.0, updateGenerateButtonText: false, cancellationToken);
				string text2 = samplePath + ".tmp";
				File.WriteAllBytes(text2, bytes);
				File.Move(text2, samplePath, overwrite: true);
			}
			soundPlayer.Stop();
			soundPlayer.SoundLocation = samplePath;
			soundPlayer.Play();
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			labelProgressStatus.Text = "Higgs sample generation cancelled.";
		}
		catch (Exception ex2)
		{
			MessageBox.Show("Higgs sample generation error: " + ex2.Message, "Higgs Sample Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
		finally
		{
			StopHiggsServer();
			higgsUseLowMemoryReference = false;
			generationInProgress = false;
			generationCancellation?.Dispose();
			generationCancellation = null;
			SetVoxGenerationControlsLocked(locked: false);
			buttonPlaySample.Enabled = true;
			buttonStopGenerated.Text = "Stop";
			buttonStopGenerated.Enabled = !string.IsNullOrWhiteSpace(lastGeneratedAudioPath) && File.Exists(lastGeneratedAudioPath);
			progressBarTts.Style = ProgressBarStyle.Blocks;
			labelProgressStatus.Text = "";
			UpdateModelStatusLabel();
		}
	}

	private async Task GenerateAndPlayHiggsAudio(string title, string text)
	{
		generationCancellation?.Dispose();
		generationCancellation = new CancellationTokenSource();
		CancellationToken cancellationToken = generationCancellation.Token;
		generationInProgress = true;
		SetVoxGenerationControlsLocked(locked: true);
		buttonPlayGenerated.Enabled = false;
		buttonStopGenerated.Enabled = true;
		buttonStopGenerated.Text = "Cancel generation";
		progressBarTts.Style = ProgressBarStyle.Marquee;
		string partialPath = "";
		bool usedMemorySafetyFallback = false;
		try
		{
			VoiceItem voice = (comboBoxVoice.SelectedItem as VoiceItem) ?? new VoiceItem("higgs_default", "Default model voice");
			ValidateHiggsVoiceReferenceOrThrow(voice.VoiceId);
			string quality = comboBoxQuality?.SelectedItem?.ToString() ?? cachedHiggsQuality;
			double speed = (double)(trackBarSpeed?.Value ?? 100) / 100.0;
			double volume = (double)(trackBarVolume?.Value ?? 100) / 100.0;
			double silence = (double)(trackBarPause?.Value ?? 25) / 100.0;
			ulong availableCommitBytes = GetAvailableCommitBytes();
			byte[] output;
			if (string.Equals(ResolveHiggsRuntimeServer(forceCpu: false).Backend, "cpu", StringComparison.OrdinalIgnoreCase) && availableCommitBytes < 12884901888L)
			{
				usedMemorySafetyFallback = true;
				AppendHiggsLog($"Higgs preflight prevented allocation crash: available commit {availableCommitBytes / 1024 / 1024} MB");
				output = await GenerateSupertonicEmergencyFallbackAsync(text, voice.VoiceId, speed, volume, silence, cancellationToken);
			}
			else
			{
				try
				{
					output = await GenerateHiggsWavAsync(text, voice.VoiceId, cachedHiggsSeed, quality, speed, volume, silence, updateGenerateButtonText: true, cancellationToken);
				}
				catch (Exception ex) when (!cancellationToken.IsCancellationRequested && (IsHiggsMemoryAllocationFailure(ex) || HasRecentHiggsMemoryAllocationFailure()))
				{
					usedMemorySafetyFallback = true;
					AppendHiggsLog("Higgs remained out of memory after recovery; completing with safety fallback");
					output = await GenerateSupertonicEmergencyFallbackAsync(text, voice.VoiceId, speed, volume, silence, cancellationToken);
				}
			}
			cancellationToken.ThrowIfCancellationRequested();
			Directory.CreateDirectory(savedAudioPath);
			string text2 = Path.Combine(savedAudioPath, $"{DateTime.Now:yyyyMMdd_HHmmss}_{title}.wav");
			partialPath = text2 + ".partial";
			File.WriteAllBytes(partialPath, output);
			File.Move(partialPath, text2, overwrite: true);
			partialPath = "";
			SetLastGeneratedAudio(text2, autoPlay: true);
			if (usedMemorySafetyFallback)
			{
				MessageBox.Show("Higgs detected low memory and used Supertonic fallback.\nRestart Windows to enable extended virtual memory for full Higgs generation.\n\nSaved: " + text2, "Memory Safety Fallback", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			}
			else
			{
				MessageBox.Show("Higgs Audio v3 voice generated.\n\nSaved: " + text2, "Success", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			labelProgressStatus.Text = "Higgs Audio v3 generation cancelled.";
		}
		catch (Exception ex3)
		{
			string text3 = ex3.Message;
			if (ex3.InnerException != null && !string.IsNullOrWhiteSpace(ex3.InnerException.Message))
			{
				text3 = text3 + "\n" + ex3.InnerException.Message;
			}
			MessageBox.Show("Higgs Audio v3 generation failed. No automatic fallback to preserve voice consistency.\n\nReason: " + text3, "Higgs Audio v3 Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
		finally
		{
			StopHiggsServer();
			higgsUseLowMemoryReference = false;
			if (!string.IsNullOrWhiteSpace(partialPath) && File.Exists(partialPath))
			{
				try
				{
					File.Delete(partialPath);
				}
				catch
				{
				}
			}
			generationInProgress = false;
			generationCancellation?.Dispose();
			generationCancellation = null;
			SetVoxGenerationControlsLocked(locked: false);
			UpdateModelStatusLabel();
			buttonGenerateAudio.Text = "Generate audio";
			buttonStopGenerated.Text = "Stop";
			progressBarTts.Style = ProgressBarStyle.Blocks;
			labelProgressStatus.Text = "";
			buttonPlayGenerated.Enabled = !string.IsNullOrWhiteSpace(lastGeneratedAudioPath) && File.Exists(lastGeneratedAudioPath);
			buttonStopGenerated.Enabled = buttonPlayGenerated.Enabled;
		}
	}

	private void StopHiggsServer()
	{
		try
		{
			if (higgsProcess != null && !higgsProcess.HasExited)
			{
				higgsProcess.Kill(entireProcessTree: true);
				higgsProcess.WaitForExit(10000);
			}
			higgsProcess?.Dispose();
		}
		catch
		{
		}
		higgsProcess = null;
		higgsPort = 0;
		StopStaleHiggsRuntimeServers();
	}

	private void InitializeComponent()
	{
		System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
		labelTitle = new Label { Text = "제목 (파일명)", AutoSize = true };
		textBoxTitle = new TextBox();
		labelContent = new Label { Text = "변환할 텍스트", AutoSize = true };
		richTextBoxContent = new RichTextBox();
		labelVoice = new Label { Text = "음성 선택", AutoSize = true };
		comboBoxVoice = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
		labelGuide = new Label { Text = "안내", AutoSize = true };
		richTextBoxGuide = new RichTextBox { ReadOnly = true };
		labelSaveDirectory = new Label { Text = "저장 폴더", AutoSize = true };
		textBoxSaveDirectory = new TextBox { ReadOnly = true };
		buttonGenerateAudio = new Button { Text = "음성 생성" };
		buttonPlaySample = new Button { Text = "샘플" };
		buttonSaveSettings = new Button { Text = "설정 저장" };
		buttonSelectFolder = new Button { Text = "..." };
		buttonOpenFolder = new Button { Text = "열기" };
		buttonLoadFile = new Button { Text = "파일 불러오기" };
		buttonOpenBlog = new Button { Text = "개발자 바로가기" };
		progressBarTts = new ProgressBar();
		labelProgressStatus = new Label { AutoSize = true };
		buttonGenerateAudio.Click += buttonGenerateAudio_Click;
		buttonPlaySample.Click += buttonPlaySample_Click;
		buttonSaveSettings.Click += buttonSaveSettings_Click;
		buttonSelectFolder.Click += buttonSelectFolder_Click;
		buttonOpenFolder.Click += buttonOpenFolder_Click;
		buttonLoadFile.Click += buttonLoadFile_Click;
		buttonOpenBlog.Click += buttonOpenBlog_Click;
		Icon icon = resources.GetObject("$this.Icon") as Icon;
		if (icon != null)
		{
			Icon = icon;
		}
		Name = "Form1";
		Text = "Supertonic + VoxCPM2";
	}
}
