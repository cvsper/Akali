#!/usr/bin/env python3
"""
Akali Training Engine - Interactive Security Training System

Delivers YAML-based training modules with lessons, code examples, and quizzes.
Tracks progress and integrates with progress_tracker.py.
"""

import yaml
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


class TrainingModule:
    """Represents a single training module loaded from YAML"""

    def __init__(self, module_path: str):
        self.path = module_path
        self.data = self._load_module()

    def _load_module(self) -> Dict[str, Any]:
        """Load and validate module YAML"""
        try:
            with open(self.path, 'r') as f:
                data = yaml.safe_load(f)

            # Validate required fields
            required = ['id', 'title', 'description', 'difficulty', 'lessons', 'quiz']
            for field in required:
                if field not in data:
                    raise ValueError(f"Missing required field: {field}")

            return data
        except Exception as e:
            raise ValueError(f"Failed to load module {self.path}: {e}")

    @property
    def id(self) -> str:
        return self.data['id']

    @property
    def title(self) -> str:
        return self.data['title']

    @property
    def description(self) -> str:
        return self.data['description']

    @property
    def difficulty(self) -> str:
        return self.data['difficulty']

    @property
    def estimated_time(self) -> str:
        return self.data.get('estimated_time', 'Unknown')

    @property
    def lessons(self) -> List[Dict[str, Any]]:
        return self.data['lessons']

    @property
    def quiz(self) -> List[Dict[str, Any]]:
        return self.data['quiz']

    @property
    def tags(self) -> List[str]:
        return self.data.get('tags', [])


class QuizEngine:
    """Handles quiz delivery and scoring"""

    def __init__(self, questions: List[Dict[str, Any]]):
        self.questions = questions
        self.answers = []
        self.score = 0
        self.total_questions = len(questions)

    def ask_question(self, question_num: int) -> Optional[str]:
        """Display a question and get user answer"""
        if question_num >= self.total_questions:
            return None

        q = self.questions[question_num]
        print(f"\n{'='*60}")
        print(f"Question {question_num + 1}/{self.total_questions}")
        print(f"{'='*60}")
        print(f"\n{q['question']}\n")

        # Display options
        for i, option in enumerate(q['options'], 1):
            print(f"  {i}. {option}")

        # Get user input
        while True:
            try:
                answer = input(f"\nYour answer (1-{len(q['options'])}): ").strip()
                answer_idx = int(answer) - 1
                if 0 <= answer_idx < len(q['options']):
                    return q['options'][answer_idx]
                else:
                    print(f"Please enter a number between 1 and {len(q['options'])}")
            except ValueError:
                print("Please enter a valid number")
            except (KeyboardInterrupt, EOFError):
                print("\n\nQuiz interrupted.")
                return None

    def check_answer(self, question_num: int, user_answer: str) -> bool:
        """Check if answer is correct and provide feedback"""
        q = self.questions[question_num]
        correct = user_answer == q['correct_answer']

        self.answers.append({
            'question': q['question'],
            'user_answer': user_answer,
            'correct_answer': q['correct_answer'],
            'correct': correct
        })

        if correct:
            self.score += 1
            print("\n✅ Correct!")
        else:
            print(f"\n❌ Incorrect. The correct answer is: {q['correct_answer']}")

        # Show explanation
        if 'explanation' in q:
            print(f"\n💡 Explanation: {q['explanation']}")

        return correct

    def run_quiz(self) -> Dict[str, Any]:
        """Run the complete quiz and return results"""
        print("\n" + "="*60)
        print("🎯 Quiz Time!")
        print("="*60)
        print("\nTest your knowledge from this module.\n")

        for i in range(self.total_questions):
            answer = self.ask_question(i)
            if answer is None:
                break
            self.check_answer(i, answer)

            # Pause between questions
            if i < self.total_questions - 1:
                input("\nPress Enter for next question...")

        # Calculate final score
        percentage = (self.score / self.total_questions) * 100 if self.total_questions > 0 else 0

        return {
            'score': self.score,
            'total': self.total_questions,
            'percentage': percentage,
            'passed': percentage >= 70,  # 70% passing grade
            'answers': self.answers
        }


class LessonDelivery:
    """Handles lesson content delivery"""

    @staticmethod
    def display_lesson(lesson: Dict[str, Any], lesson_num: int, total_lessons: int):
        """Display a single lesson with formatting"""
        print("\n" + "="*60)
        print(f"📚 Lesson {lesson_num}/{total_lessons}: {lesson['title']}")
        print("="*60 + "\n")

        # Display content sections
        if 'content' in lesson:
            for section in lesson['content']:
                if section['type'] == 'text':
                    print(section['value'])
                    print()
                elif section['type'] == 'code':
                    lang = section.get('language', 'text')
                    print(f"```{lang}")
                    print(section['value'])
                    print("```")
                    print()
                elif section['type'] == 'warning':
                    print(f"⚠️  WARNING: {section['value']}")
                    print()
                elif section['type'] == 'tip':
                    print(f"💡 TIP: {section['value']}")
                    print()
                elif section['type'] == 'example':
                    print(f"📝 Example:")
                    print(section['value'])
                    print()

        # Display key takeaways
        if 'takeaways' in lesson:
            print("\n🎯 Key Takeaways:")
            for takeaway in lesson['takeaways']:
                print(f"  • {takeaway}")
            print()


class TrainingEngine:
    """Main training engine - orchestrates module delivery"""

    def __init__(self, modules_dir: str = None):
        if modules_dir is None:
            # Default to akali/education/training/modules/
            base_dir = Path(__file__).parent
            modules_dir = base_dir / "modules"

        self.modules_dir = Path(modules_dir)
        self.available_modules = self._scan_modules()

    def _scan_modules(self) -> Dict[str, TrainingModule]:
        """Scan modules directory and load all YAML modules"""
        modules = {}

        if not self.modules_dir.exists():
            return modules

        for module_file in self.modules_dir.glob("*.yaml"):
            try:
                module = TrainingModule(str(module_file))
                modules[module.id] = module
            except Exception as e:
                print(f"Warning: Failed to load {module_file.name}: {e}", file=sys.stderr)

        return modules

    def list_modules(self) -> List[Dict[str, str]]:
        """Return list of available modules with metadata"""
        return [
            {
                'id': m.id,
                'title': m.title,
                'description': m.description,
                'difficulty': m.difficulty,
                'estimated_time': m.estimated_time,
                'tags': m.tags
            }
            for m in self.available_modules.values()
        ]

    def get_module(self, module_id: str) -> Optional[TrainingModule]:
        """Get a specific module by ID"""
        return self.available_modules.get(module_id)

    def start_training(self, module_id: str, agent_id: str = "unknown") -> Dict[str, Any]:
        """Start training session for a module"""
        module = self.get_module(module_id)
        if not module:
            return {'error': f'Module not found: {module_id}'}

        print("\n" + "🥷 "*20)
        print(f"Akali Security Training: {module.title}")
        print("🥷 "*20)
        print(f"\n📋 Description: {module.description}")
        print(f"⏱️  Estimated Time: {module.estimated_time}")
        print(f"📊 Difficulty: {module.difficulty}")

        if module.tags:
            print(f"🏷️  Tags: {', '.join(module.tags)}")

        print("\n" + "-"*60)
        input("\nPress Enter to begin training...")

        # Deliver lessons
        total_lessons = len(module.lessons)
        for i, lesson in enumerate(module.lessons, 1):
            LessonDelivery.display_lesson(lesson, i, total_lessons)

            if i < total_lessons:
                input("\nPress Enter to continue to next lesson...")

        # Run quiz
        print("\n" + "="*60)
        print("📝 You've completed all lessons!")
        print("="*60)
        input("\nPress Enter to start the quiz...")

        quiz = QuizEngine(module.quiz)
        quiz_results = quiz.run_quiz()

        # Display final results
        print("\n" + "="*60)
        print("🎓 Training Complete!")
        print("="*60)
        print(f"\nFinal Score: {quiz_results['score']}/{quiz_results['total']} ({quiz_results['percentage']:.1f}%)")

        if quiz_results['passed']:
            print("\n✅ Congratulations! You passed!")
            print("🏆 You've earned a certificate for this module.")
        else:
            print("\n❌ You did not pass (70% required).")
            print("💪 Keep learning and try again!")

        # Return session results
        return {
            'module_id': module_id,
            'agent_id': agent_id,
            'completed': True,
            'passed': quiz_results['passed'],
            'score': quiz_results['score'],
            'total_questions': quiz_results['total'],
            'percentage': quiz_results['percentage'],
            'timestamp': datetime.now().isoformat(),
            'answers': quiz_results['answers']
        }


def main():
    """CLI entry point for testing"""
    engine = TrainingEngine()

    # List available modules
    modules = engine.list_modules()

    if not modules:
        print("No training modules found.")
        return

    print("\n🥷 Akali Training Modules:\n")
    for i, module in enumerate(modules, 1):
        print(f"{i}. {module['title']}")
        print(f"   {module['description']}")
        print(f"   Difficulty: {module['difficulty']} | Time: {module['estimated_time']}")
        print()

    # Get user choice
    try:
        choice = int(input("Select a module (number): "))
        if 1 <= choice <= len(modules):
            module_id = modules[choice - 1]['id']
            results = engine.start_training(module_id)
            print(f"\n📊 Results: {json.dumps(results, indent=2)}")
        else:
            print("Invalid choice.")
    except (ValueError, KeyboardInterrupt):
        print("\nExiting.")


if __name__ == '__main__':
    main()
